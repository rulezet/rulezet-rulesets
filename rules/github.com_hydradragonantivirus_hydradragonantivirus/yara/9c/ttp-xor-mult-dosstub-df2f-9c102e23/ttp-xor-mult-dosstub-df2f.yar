rule TTP_XOR_MULT_DOSStub_df2f {
  strings:
    $key_df2f = { 8b 47 [2] ff 5f [2] b8 5d [2] ff 4c [2] b1 40 [2] bd 4a [2] aa 41 [2] b1 0f [2] 8c }

  condition:
    any of them
}