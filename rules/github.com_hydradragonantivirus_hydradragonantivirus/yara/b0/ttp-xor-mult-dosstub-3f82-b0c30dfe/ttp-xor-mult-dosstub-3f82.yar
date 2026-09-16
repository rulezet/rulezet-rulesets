rule TTP_XOR_MULT_DOSStub_3f82 {
  strings:
    $key_3f82 = { 6b ea [2] 1f f2 [2] 58 f0 [2] 1f e1 [2] 51 ed [2] 5d e7 [2] 4a ec [2] 51 a2 [2] 6c }

  condition:
    any of them
}