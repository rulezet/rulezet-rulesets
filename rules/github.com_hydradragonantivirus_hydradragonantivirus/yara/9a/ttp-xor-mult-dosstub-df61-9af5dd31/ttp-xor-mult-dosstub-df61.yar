rule TTP_XOR_MULT_DOSStub_df61 {
  strings:
    $key_df61 = { 8b 09 [2] ff 11 [2] b8 13 [2] ff 02 [2] b1 0e [2] bd 04 [2] aa 0f [2] b1 41 [2] 8c }

  condition:
    any of them
}