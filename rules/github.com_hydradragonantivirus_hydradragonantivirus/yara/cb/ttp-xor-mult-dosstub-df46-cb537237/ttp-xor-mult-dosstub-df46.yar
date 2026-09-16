rule TTP_XOR_MULT_DOSStub_df46 {
  strings:
    $key_df46 = { 8b 2e [2] ff 36 [2] b8 34 [2] ff 25 [2] b1 29 [2] bd 23 [2] aa 28 [2] b1 66 [2] 8c }

  condition:
    any of them
}