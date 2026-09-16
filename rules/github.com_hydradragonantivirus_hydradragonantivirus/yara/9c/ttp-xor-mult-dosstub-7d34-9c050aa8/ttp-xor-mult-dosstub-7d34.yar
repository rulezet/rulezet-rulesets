rule TTP_XOR_MULT_DOSStub_7d34 {
  strings:
    $key_7d34 = { 29 5c [2] 5d 44 [2] 1a 46 [2] 5d 57 [2] 13 5b [2] 1f 51 [2] 08 5a [2] 13 14 [2] 2e }

  condition:
    any of them
}