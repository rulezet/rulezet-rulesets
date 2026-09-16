rule TTP_XOR_MULT_DOSStub_df88 {
  strings:
    $key_df88 = { 8b e0 [2] ff f8 [2] b8 fa [2] ff eb [2] b1 e7 [2] bd ed [2] aa e6 [2] b1 a8 [2] 8c }

  condition:
    any of them
}