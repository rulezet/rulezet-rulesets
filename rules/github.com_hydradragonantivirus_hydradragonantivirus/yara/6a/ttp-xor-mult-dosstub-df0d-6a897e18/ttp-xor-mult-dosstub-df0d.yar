rule TTP_XOR_MULT_DOSStub_df0d {
  strings:
    $key_df0d = { 8b 65 [2] ff 7d [2] b8 7f [2] ff 6e [2] b1 62 [2] bd 68 [2] aa 63 [2] b1 2d [2] 8c }

  condition:
    any of them
}