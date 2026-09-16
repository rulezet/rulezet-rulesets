rule TTP_XOR_MULT_DOSStub_e684 {
  strings:
    $key_e684 = { b2 ec [2] c6 f4 [2] 81 f6 [2] c6 e7 [2] 88 eb [2] 84 e1 [2] 93 ea [2] 88 a4 [2] b5 }

  condition:
    any of them
}