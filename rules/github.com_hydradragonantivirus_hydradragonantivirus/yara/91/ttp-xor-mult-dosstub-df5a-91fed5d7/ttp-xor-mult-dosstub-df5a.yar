rule TTP_XOR_MULT_DOSStub_df5a {
  strings:
    $key_df5a = { 8b 32 [2] ff 2a [2] b8 28 [2] ff 39 [2] b1 35 [2] bd 3f [2] aa 34 [2] b1 7a [2] 8c }

  condition:
    any of them
}