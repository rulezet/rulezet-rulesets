rule TTP_XOR_MULT_DOSStub_1854 {
  strings:
    $key_1854 = { 4c 3c [2] 38 24 [2] 7f 26 [2] 38 37 [2] 76 3b [2] 7a 31 [2] 6d 3a [2] 76 74 [2] 4b }

  condition:
    any of them
}