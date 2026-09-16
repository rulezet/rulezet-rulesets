rule TTP_XOR_MULT_DOSStub_74b1 {
  strings:
    $key_74b1 = { 20 d9 [2] 54 c1 [2] 13 c3 [2] 54 d2 [2] 1a de [2] 16 d4 [2] 01 df [2] 1a 91 [2] 27 }

  condition:
    any of them
}