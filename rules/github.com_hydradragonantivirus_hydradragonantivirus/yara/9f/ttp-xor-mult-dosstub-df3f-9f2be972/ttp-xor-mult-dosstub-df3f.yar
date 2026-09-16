rule TTP_XOR_MULT_DOSStub_df3f {
  strings:
    $key_df3f = { 8b 57 [2] ff 4f [2] b8 4d [2] ff 5c [2] b1 50 [2] bd 5a [2] aa 51 [2] b1 1f [2] 8c }

  condition:
    any of them
}