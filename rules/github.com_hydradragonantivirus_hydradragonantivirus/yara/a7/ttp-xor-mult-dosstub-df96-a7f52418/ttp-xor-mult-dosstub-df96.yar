rule TTP_XOR_MULT_DOSStub_df96 {
  strings:
    $key_df96 = { 8b fe [2] ff e6 [2] b8 e4 [2] ff f5 [2] b1 f9 [2] bd f3 [2] aa f8 [2] b1 b6 [2] 8c }

  condition:
    any of them
}