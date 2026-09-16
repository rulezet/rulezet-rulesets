rule TTP_XOR_MULT_DOSStub_df5b {
  strings:
    $key_df5b = { 8b 33 [2] ff 2b [2] b8 29 [2] ff 38 [2] b1 34 [2] bd 3e [2] aa 35 [2] b1 7b [2] 8c }

  condition:
    any of them
}