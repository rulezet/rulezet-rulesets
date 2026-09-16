rule TTP_XOR_MULT_DOSStub_df18 {
  strings:
    $key_df18 = { 8b 70 [2] ff 68 [2] b8 6a [2] ff 7b [2] b1 77 [2] bd 7d [2] aa 76 [2] b1 38 [2] 8c }

  condition:
    any of them
}