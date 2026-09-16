rule TTP_XOR_MULT_DOSStub_5883 {
  strings:
    $key_5883 = { 0c eb [2] 78 f3 [2] 3f f1 [2] 78 e0 [2] 36 ec [2] 3a e6 [2] 2d ed [2] 36 a3 [2] 0b }

  condition:
    any of them
}