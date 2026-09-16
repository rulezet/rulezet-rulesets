rule TTP_XOR_MULT_DOSStub_4985 {
  strings:
    $key_4985 = { 1d ed [2] 69 f5 [2] 2e f7 [2] 69 e6 [2] 27 ea [2] 2b e0 [2] 3c eb [2] 27 a5 [2] 1a }

  condition:
    any of them
}