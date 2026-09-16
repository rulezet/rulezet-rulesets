rule TTP_XOR_MULT_DOSStub_df00 {
  strings:
    $key_df00 = { 8b 68 [2] ff 70 [2] b8 72 [2] ff 63 [2] b1 6f [2] bd 65 [2] aa 6e [2] b1 20 [2] 8c }

  condition:
    any of them
}