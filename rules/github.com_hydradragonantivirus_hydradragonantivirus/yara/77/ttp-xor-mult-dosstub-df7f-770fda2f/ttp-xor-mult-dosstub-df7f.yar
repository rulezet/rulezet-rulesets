rule TTP_XOR_MULT_DOSStub_df7f {
  strings:
    $key_df7f = { 8b 17 [2] ff 0f [2] b8 0d [2] ff 1c [2] b1 10 [2] bd 1a [2] aa 11 [2] b1 5f [2] 8c }

  condition:
    any of them
}