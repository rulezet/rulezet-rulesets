rule TTP_XOR_MULT_DOSStub_4f83 {
  strings:
    $key_4f83 = { 1b eb [2] 6f f3 [2] 28 f1 [2] 6f e0 [2] 21 ec [2] 2d e6 [2] 3a ed [2] 21 a3 [2] 1c }

  condition:
    any of them
}