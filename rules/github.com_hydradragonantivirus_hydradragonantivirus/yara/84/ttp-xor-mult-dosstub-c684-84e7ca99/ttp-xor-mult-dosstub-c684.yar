rule TTP_XOR_MULT_DOSStub_c684 {
  strings:
    $key_c684 = { 92 ec [2] e6 f4 [2] a1 f6 [2] e6 e7 [2] a8 eb [2] a4 e1 [2] b3 ea [2] a8 a4 [2] 95 }

  condition:
    any of them
}