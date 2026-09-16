rule TTP_XOR_MULT_DOSStub_df68 {
  strings:
    $key_df68 = { 8b 00 [2] ff 18 [2] b8 1a [2] ff 0b [2] b1 07 [2] bd 0d [2] aa 06 [2] b1 48 [2] 8c }

  condition:
    any of them
}