rule TTP_XOR_MULT_DOSStub_6f82 {
  strings:
    $key_6f82 = { 3b ea [2] 4f f2 [2] 08 f0 [2] 4f e1 [2] 01 ed [2] 0d e7 [2] 1a ec [2] 01 a2 [2] 3c }

  condition:
    any of them
}