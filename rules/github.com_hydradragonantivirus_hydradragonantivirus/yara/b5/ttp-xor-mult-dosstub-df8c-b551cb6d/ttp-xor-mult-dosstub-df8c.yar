rule TTP_XOR_MULT_DOSStub_df8c {
  strings:
    $key_df8c = { 8b e4 [2] ff fc [2] b8 fe [2] ff ef [2] b1 e3 [2] bd e9 [2] aa e2 [2] b1 ac [2] 8c }

  condition:
    any of them
}