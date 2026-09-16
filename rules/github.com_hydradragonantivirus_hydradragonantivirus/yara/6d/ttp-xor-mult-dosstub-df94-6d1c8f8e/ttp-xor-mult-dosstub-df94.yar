rule TTP_XOR_MULT_DOSStub_df94 {
  strings:
    $key_df94 = { 8b fc [2] ff e4 [2] b8 e6 [2] ff f7 [2] b1 fb [2] bd f1 [2] aa fa [2] b1 b4 [2] 8c }

  condition:
    any of them
}