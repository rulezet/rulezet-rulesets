rule TTP_XOR_MULT_DOSStub_4d35 {
  strings:
    $key_4d35 = { 19 5d [2] 6d 45 [2] 2a 47 [2] 6d 56 [2] 23 5a [2] 2f 50 [2] 38 5b [2] 23 15 [2] 1e }

  condition:
    any of them
}