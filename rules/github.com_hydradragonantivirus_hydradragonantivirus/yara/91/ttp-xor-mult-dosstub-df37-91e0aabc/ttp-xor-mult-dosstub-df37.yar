rule TTP_XOR_MULT_DOSStub_df37 {
  strings:
    $key_df37 = { 8b 5f [2] ff 47 [2] b8 45 [2] ff 54 [2] b1 58 [2] bd 52 [2] aa 59 [2] b1 17 [2] 8c }

  condition:
    any of them
}