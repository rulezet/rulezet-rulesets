rule TTP_XOR_MULT_DOSStub_7883 {
  strings:
    $key_7883 = { 2c eb [2] 58 f3 [2] 1f f1 [2] 58 e0 [2] 16 ec [2] 1a e6 [2] 0d ed [2] 16 a3 [2] 2b }

  condition:
    any of them
}