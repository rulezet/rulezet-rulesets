rule TTP_XOR_MULT_DOSStub_74e8 {
  strings:
    $key_74e8 = { 20 80 [2] 54 98 [2] 13 9a [2] 54 8b [2] 1a 87 [2] 16 8d [2] 01 86 [2] 1a c8 [2] 27 }

  condition:
    any of them
}