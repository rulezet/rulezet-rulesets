rule TTP_XOR_MULT_DOSStub_6d35 {
  strings:
    $key_6d35 = { 39 5d [2] 4d 45 [2] 0a 47 [2] 4d 56 [2] 03 5a [2] 0f 50 [2] 18 5b [2] 03 15 [2] 3e }

  condition:
    any of them
}