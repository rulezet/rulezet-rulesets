rule TTP_XOR_MULT_DOSStub_df0a {
  strings:
    $key_df0a = { 8b 62 [2] ff 7a [2] b8 78 [2] ff 69 [2] b1 65 [2] bd 6f [2] aa 64 [2] b1 2a [2] 8c }

  condition:
    any of them
}