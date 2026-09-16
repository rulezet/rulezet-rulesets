rule TTP_XOR_MULT_DOSStub_df5f {
  strings:
    $key_df5f = { 8b 37 [2] ff 2f [2] b8 2d [2] ff 3c [2] b1 30 [2] bd 3a [2] aa 31 [2] b1 7f [2] 8c }

  condition:
    any of them
}