rule TTP_XOR_MULT_DOSStub_7985 {
  strings:
    $key_7985 = { 2d ed [2] 59 f5 [2] 1e f7 [2] 59 e6 [2] 17 ea [2] 1b e0 [2] 0c eb [2] 17 a5 [2] 2a }

  condition:
    any of them
}