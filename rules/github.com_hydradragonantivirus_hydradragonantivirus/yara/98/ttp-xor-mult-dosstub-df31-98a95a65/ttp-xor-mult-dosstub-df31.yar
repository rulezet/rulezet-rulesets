rule TTP_XOR_MULT_DOSStub_df31 {
  strings:
    $key_df31 = { 8b 59 [2] ff 41 [2] b8 43 [2] ff 52 [2] b1 5e [2] bd 54 [2] aa 5f [2] b1 11 [2] 8c }

  condition:
    any of them
}