rule TTP_XOR_MULT_DOSStub_df36 {
  strings:
    $key_df36 = { 8b 5e [2] ff 46 [2] b8 44 [2] ff 55 [2] b1 59 [2] bd 53 [2] aa 58 [2] b1 16 [2] 8c }

  condition:
    any of them
}