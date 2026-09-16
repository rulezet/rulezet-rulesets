rule TTP_XOR_MULT_DOSStub_5885 {
  strings:
    $key_5885 = { 0c ed [2] 78 f5 [2] 3f f7 [2] 78 e6 [2] 36 ea [2] 3a e0 [2] 2d eb [2] 36 a5 [2] 0b }

  condition:
    any of them
}