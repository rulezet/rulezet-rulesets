rule TTP_XOR_MULT_DOSStub_df72 {
  strings:
    $key_df72 = { 8b 1a [2] ff 02 [2] b8 00 [2] ff 11 [2] b1 1d [2] bd 17 [2] aa 1c [2] b1 52 [2] 8c }

  condition:
    any of them
}