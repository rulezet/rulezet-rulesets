rule TTP_XOR_MULT_DOSStub_df3a {
  strings:
    $key_df3a = { 8b 52 [2] ff 4a [2] b8 48 [2] ff 59 [2] b1 55 [2] bd 5f [2] aa 54 [2] b1 1a [2] 8c }

  condition:
    any of them
}