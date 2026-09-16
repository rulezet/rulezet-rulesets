rule TTP_XOR_MULT_DOSStub_df12 {
  strings:
    $key_df12 = { 8b 7a [2] ff 62 [2] b8 60 [2] ff 71 [2] b1 7d [2] bd 77 [2] aa 7c [2] b1 32 [2] 8c }

  condition:
    any of them
}