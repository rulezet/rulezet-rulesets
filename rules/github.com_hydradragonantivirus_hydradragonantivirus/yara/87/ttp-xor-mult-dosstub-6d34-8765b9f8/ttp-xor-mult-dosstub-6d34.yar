rule TTP_XOR_MULT_DOSStub_6d34 {
  strings:
    $key_6d34 = { 39 5c [2] 4d 44 [2] 0a 46 [2] 4d 57 [2] 03 5b [2] 0f 51 [2] 18 5a [2] 03 14 [2] 3e }

  condition:
    any of them
}