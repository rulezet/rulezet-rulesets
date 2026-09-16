rule TTP_XOR_MULT_DOSStub_74e9 {
  strings:
    $key_74e9 = { 20 81 [2] 54 99 [2] 13 9b [2] 54 8a [2] 1a 86 [2] 16 8c [2] 01 87 [2] 1a c9 [2] 27 }

  condition:
    any of them
}