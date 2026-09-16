rule TTP_XOR_MULT_DOSStub_df19 {
  strings:
    $key_df19 = { 8b 71 [2] ff 69 [2] b8 6b [2] ff 7a [2] b1 76 [2] bd 7c [2] aa 77 [2] b1 39 [2] 8c }

  condition:
    any of them
}