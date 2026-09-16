rule TTP_XOR_MULT_DOSStub_6885 {
  strings:
    $key_6885 = { 3c ed [2] 48 f5 [2] 0f f7 [2] 48 e6 [2] 06 ea [2] 0a e0 [2] 1d eb [2] 06 a5 [2] 3b }

  condition:
    any of them
}