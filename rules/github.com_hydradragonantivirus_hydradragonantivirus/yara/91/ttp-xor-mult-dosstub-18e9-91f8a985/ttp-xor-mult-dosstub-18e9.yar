rule TTP_XOR_MULT_DOSStub_18e9 {
  strings:
    $key_18e9 = { 4c 81 [2] 38 99 [2] 7f 9b [2] 38 8a [2] 76 86 [2] 7a 8c [2] 6d 87 [2] 76 c9 [2] 4b }

  condition:
    any of them
}