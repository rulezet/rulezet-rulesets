rule TTP_XOR_MULT_DOSStub_df40 {
  strings:
    $key_df40 = { 8b 28 [2] ff 30 [2] b8 32 [2] ff 23 [2] b1 2f [2] bd 25 [2] aa 2e [2] b1 60 [2] 8c }

  condition:
    any of them
}