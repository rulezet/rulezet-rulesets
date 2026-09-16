rule TTP_XOR_MULT_DOSStub_7f82 {
  strings:
    $key_7f82 = { 2b ea [2] 5f f2 [2] 18 f0 [2] 5f e1 [2] 11 ed [2] 1d e7 [2] 0a ec [2] 11 a2 [2] 2c }

  condition:
    any of them
}