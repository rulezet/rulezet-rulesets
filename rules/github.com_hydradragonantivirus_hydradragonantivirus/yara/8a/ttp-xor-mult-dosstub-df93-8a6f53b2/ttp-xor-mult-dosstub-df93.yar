rule TTP_XOR_MULT_DOSStub_df93 {
  strings:
    $key_df93 = { 8b fb [2] ff e3 [2] b8 e1 [2] ff f0 [2] b1 fc [2] bd f6 [2] aa fd [2] b1 b3 [2] 8c }

  condition:
    any of them
}