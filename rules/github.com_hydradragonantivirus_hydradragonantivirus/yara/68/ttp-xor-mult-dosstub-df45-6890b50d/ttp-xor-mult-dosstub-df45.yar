rule TTP_XOR_MULT_DOSStub_df45 {
  strings:
    $key_df45 = { 8b 2d [2] ff 35 [2] b8 37 [2] ff 26 [2] b1 2a [2] bd 20 [2] aa 2b [2] b1 65 [2] 8c }

  condition:
    any of them
}