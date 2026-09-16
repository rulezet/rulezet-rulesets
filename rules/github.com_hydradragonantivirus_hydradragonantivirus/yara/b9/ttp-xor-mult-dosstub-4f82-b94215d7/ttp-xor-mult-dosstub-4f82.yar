rule TTP_XOR_MULT_DOSStub_4f82 {
  strings:
    $key_4f82 = { 1b ea [2] 6f f2 [2] 28 f0 [2] 6f e1 [2] 21 ed [2] 2d e7 [2] 3a ec [2] 21 a2 [2] 1c }

  condition:
    any of them
}