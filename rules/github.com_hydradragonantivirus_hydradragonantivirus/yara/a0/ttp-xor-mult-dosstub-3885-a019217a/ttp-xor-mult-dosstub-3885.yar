rule TTP_XOR_MULT_DOSStub_3885 {
  strings:
    $key_3885 = { 6c ed [2] 18 f5 [2] 5f f7 [2] 18 e6 [2] 56 ea [2] 5a e0 [2] 4d eb [2] 56 a5 [2] 6b }

  condition:
    any of them
}