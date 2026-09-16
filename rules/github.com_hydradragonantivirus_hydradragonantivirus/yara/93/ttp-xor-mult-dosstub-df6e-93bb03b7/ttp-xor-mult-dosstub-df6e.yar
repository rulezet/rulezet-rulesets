rule TTP_XOR_MULT_DOSStub_df6e {
  strings:
    $key_df6e = { 8b 06 [2] ff 1e [2] b8 1c [2] ff 0d [2] b1 01 [2] bd 0b [2] aa 00 [2] b1 4e [2] 8c }

  condition:
    any of them
}