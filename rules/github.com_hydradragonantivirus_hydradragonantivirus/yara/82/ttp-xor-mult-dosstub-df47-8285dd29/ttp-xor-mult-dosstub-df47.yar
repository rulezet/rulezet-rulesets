rule TTP_XOR_MULT_DOSStub_df47 {
  strings:
    $key_df47 = { 8b 2f [2] ff 37 [2] b8 35 [2] ff 24 [2] b1 28 [2] bd 22 [2] aa 29 [2] b1 67 [2] 8c }

  condition:
    any of them
}