rule TTP_XOR_MULT_DOSStub_4f84 {
  strings:
    $key_4f84 = { 1b ec [2] 6f f4 [2] 28 f6 [2] 6f e7 [2] 21 eb [2] 2d e1 [2] 3a ea [2] 21 a4 [2] 1c }

  condition:
    any of them
}