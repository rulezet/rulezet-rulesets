rule TTP_XOR_MULT_DOSStub_7982 {
  strings:
    $key_7982 = { 2d ea [2] 59 f2 [2] 1e f0 [2] 59 e1 [2] 17 ed [2] 1b e7 [2] 0c ec [2] 17 a2 [2] 2a }

  condition:
    any of them
}