rule TTP_XOR_MULT_DOSStub_6ce9 {
  strings:
    $key_6ce9 = { 38 81 [2] 4c 99 [2] 0b 9b [2] 4c 8a [2] 02 86 [2] 0e 8c [2] 19 87 [2] 02 c9 [2] 3f }

  condition:
    any of them
}