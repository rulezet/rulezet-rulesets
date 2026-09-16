rule TTP_XOR_MULT_DOSStub_1885 {
  strings:
    $key_1885 = { 4c ed [2] 38 f5 [2] 7f f7 [2] 38 e6 [2] 76 ea [2] 7a e0 [2] 6d eb [2] 76 a5 [2] 4b }

  condition:
    any of them
}