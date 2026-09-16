rule TTP_XOR_MULT_DOSStub_df26 {
  strings:
    $key_df26 = { 8b 4e [2] ff 56 [2] b8 54 [2] ff 45 [2] b1 49 [2] bd 43 [2] aa 48 [2] b1 06 [2] 8c }

  condition:
    any of them
}