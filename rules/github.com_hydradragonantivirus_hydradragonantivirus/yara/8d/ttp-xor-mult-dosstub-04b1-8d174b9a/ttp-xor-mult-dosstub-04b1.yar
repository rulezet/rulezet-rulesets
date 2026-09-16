rule TTP_XOR_MULT_DOSStub_04b1 {
  strings:
    $key_04b1 = { 50 d9 [2] 24 c1 [2] 63 c3 [2] 24 d2 [2] 6a de [2] 66 d4 [2] 71 df [2] 6a 91 [2] 57 }

  condition:
    any of them
}