rule TTP_XOR_MULT_DOSStub_df48 {
  strings:
    $key_df48 = { 8b 20 [2] ff 38 [2] b8 3a [2] ff 2b [2] b1 27 [2] bd 2d [2] aa 26 [2] b1 68 [2] 8c }

  condition:
    any of them
}