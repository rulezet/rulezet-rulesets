rule TTP_XOR_MULT_DOSStub_df55 {
  strings:
    $key_df55 = { 8b 3d [2] ff 25 [2] b8 27 [2] ff 36 [2] b1 3a [2] bd 30 [2] aa 3b [2] b1 75 [2] 8c }

  condition:
    any of them
}