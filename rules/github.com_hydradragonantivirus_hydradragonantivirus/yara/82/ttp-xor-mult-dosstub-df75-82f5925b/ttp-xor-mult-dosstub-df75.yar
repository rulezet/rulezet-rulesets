rule TTP_XOR_MULT_DOSStub_df75 {
  strings:
    $key_df75 = { 8b 1d [2] ff 05 [2] b8 07 [2] ff 16 [2] b1 1a [2] bd 10 [2] aa 1b [2] b1 55 [2] 8c }

  condition:
    any of them
}