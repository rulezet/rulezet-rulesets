rule TTP_XOR_MULT_DOSStub_3982 {
  strings:
    $key_3982 = { 6d ea [2] 19 f2 [2] 5e f0 [2] 19 e1 [2] 57 ed [2] 5b e7 [2] 4c ec [2] 57 a2 [2] 6a }

  condition:
    any of them
}