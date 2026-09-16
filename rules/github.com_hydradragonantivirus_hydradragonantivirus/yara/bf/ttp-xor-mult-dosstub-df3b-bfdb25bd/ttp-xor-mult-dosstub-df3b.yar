rule TTP_XOR_MULT_DOSStub_df3b {
  strings:
    $key_df3b = { 8b 53 [2] ff 4b [2] b8 49 [2] ff 58 [2] b1 54 [2] bd 5e [2] aa 55 [2] b1 1b [2] 8c }

  condition:
    any of them
}