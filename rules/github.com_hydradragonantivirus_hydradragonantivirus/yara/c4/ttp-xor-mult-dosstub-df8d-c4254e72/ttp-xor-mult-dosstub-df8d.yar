rule TTP_XOR_MULT_DOSStub_df8d {
  strings:
    $key_df8d = { 8b e5 [2] ff fd [2] b8 ff [2] ff ee [2] b1 e2 [2] bd e8 [2] aa e3 [2] b1 ad [2] 8c }

  condition:
    any of them
}