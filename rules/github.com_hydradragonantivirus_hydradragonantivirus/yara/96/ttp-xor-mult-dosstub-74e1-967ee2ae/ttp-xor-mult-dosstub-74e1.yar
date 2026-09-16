rule TTP_XOR_MULT_DOSStub_74e1 {
  strings:
    $key_74e1 = { 20 89 [2] 54 91 [2] 13 93 [2] 54 82 [2] 1a 8e [2] 16 84 [2] 01 8f [2] 1a c1 [2] 27 }

  condition:
    any of them
}