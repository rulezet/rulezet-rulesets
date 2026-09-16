rule TTP_XOR_MULT_DOSStub_dfc6 {
  strings:
    $key_dfc6 = { 8b ae [2] ff b6 [2] b8 b4 [2] ff a5 [2] b1 a9 [2] bd a3 [2] aa a8 [2] b1 e6 [2] 8c }

  condition:
    any of them
}