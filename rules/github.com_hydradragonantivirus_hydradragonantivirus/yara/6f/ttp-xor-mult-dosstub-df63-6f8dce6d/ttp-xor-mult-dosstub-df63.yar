rule TTP_XOR_MULT_DOSStub_df63 {
  strings:
    $key_df63 = { 8b 0b [2] ff 13 [2] b8 11 [2] ff 00 [2] b1 0c [2] bd 06 [2] aa 0d [2] b1 43 [2] 8c }

  condition:
    any of them
}