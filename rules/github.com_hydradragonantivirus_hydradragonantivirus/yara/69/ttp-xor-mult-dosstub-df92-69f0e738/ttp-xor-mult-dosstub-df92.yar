rule TTP_XOR_MULT_DOSStub_df92 {
  strings:
    $key_df92 = { 8b fa [2] ff e2 [2] b8 e0 [2] ff f1 [2] b1 fd [2] bd f7 [2] aa fc [2] b1 b2 [2] 8c }

  condition:
    any of them
}