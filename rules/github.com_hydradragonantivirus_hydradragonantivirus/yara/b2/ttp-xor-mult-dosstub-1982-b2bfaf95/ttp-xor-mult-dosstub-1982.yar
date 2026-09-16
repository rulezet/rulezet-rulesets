rule TTP_XOR_MULT_DOSStub_1982 {
  strings:
    $key_1982 = { 4d ea [2] 39 f2 [2] 7e f0 [2] 39 e1 [2] 77 ed [2] 7b e7 [2] 6c ec [2] 77 a2 [2] 4a }

  condition:
    any of them
}