rule TTP_XOR_MULT_DOSStub_df8f {
  strings:
    $key_df8f = { 8b e7 [2] ff ff [2] b8 fd [2] ff ec [2] b1 e0 [2] bd ea [2] aa e1 [2] b1 af [2] 8c }

  condition:
    any of them
}