rule TTP_XOR_MULT_DOSStub_c784 {
  strings:
    $key_c784 = { 93 ec [2] e7 f4 [2] a0 f6 [2] e7 e7 [2] a9 eb [2] a5 e1 [2] b2 ea [2] a9 a4 [2] 94 }

  condition:
    any of them
}