rule TTP_XOR_MULT_DOSStub_df2c {
  strings:
    $key_df2c = { 8b 44 [2] ff 5c [2] b8 5e [2] ff 4f [2] b1 43 [2] bd 49 [2] aa 42 [2] b1 0c [2] 8c }

  condition:
    any of them
}