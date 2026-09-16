rule TTP_XOR_MULT_DOSStub_e4b1 {
  strings:
    $key_e4b1 = { b0 d9 [2] c4 c1 [2] 83 c3 [2] c4 d2 [2] 8a de [2] 86 d4 [2] 91 df [2] 8a 91 [2] b7 }

  condition:
    any of them
}