rule TTP_XOR_MULT_DOSStub_74e4 {
  strings:
    $key_74e4 = { 20 8c [2] 54 94 [2] 13 96 [2] 54 87 [2] 1a 8b [2] 16 81 [2] 01 8a [2] 1a c4 [2] 27 }

  condition:
    any of them
}