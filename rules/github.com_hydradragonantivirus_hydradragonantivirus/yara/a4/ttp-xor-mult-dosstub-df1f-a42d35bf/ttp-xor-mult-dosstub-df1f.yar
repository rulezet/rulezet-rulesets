rule TTP_XOR_MULT_DOSStub_df1f {
  strings:
    $key_df1f = { 8b 77 [2] ff 6f [2] b8 6d [2] ff 7c [2] b1 70 [2] bd 7a [2] aa 71 [2] b1 3f [2] 8c }

  condition:
    any of them
}