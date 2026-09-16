rule TTP_XOR_MULT_DOSStub_5985 {
  strings:
    $key_5985 = { 0d ed [2] 79 f5 [2] 3e f7 [2] 79 e6 [2] 37 ea [2] 3b e0 [2] 2c eb [2] 37 a5 [2] 0a }

  condition:
    any of them
}