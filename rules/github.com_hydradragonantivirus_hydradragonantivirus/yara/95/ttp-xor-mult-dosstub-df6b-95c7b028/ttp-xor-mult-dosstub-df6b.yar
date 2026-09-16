rule TTP_XOR_MULT_DOSStub_df6b {
  strings:
    $key_df6b = { 8b 03 [2] ff 1b [2] b8 19 [2] ff 08 [2] b1 04 [2] bd 0e [2] aa 05 [2] b1 4b [2] 8c }

  condition:
    any of them
}