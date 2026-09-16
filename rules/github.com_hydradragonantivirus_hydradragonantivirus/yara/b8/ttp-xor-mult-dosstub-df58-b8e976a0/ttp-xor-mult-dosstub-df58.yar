rule TTP_XOR_MULT_DOSStub_df58 {
  strings:
    $key_df58 = { 8b 30 [2] ff 28 [2] b8 2a [2] ff 3b [2] b1 37 [2] bd 3d [2] aa 36 [2] b1 78 [2] 8c }

  condition:
    any of them
}