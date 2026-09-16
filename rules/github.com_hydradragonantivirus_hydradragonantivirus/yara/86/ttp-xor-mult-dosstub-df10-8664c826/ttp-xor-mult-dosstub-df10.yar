rule TTP_XOR_MULT_DOSStub_df10 {
  strings:
    $key_df10 = { 8b 78 [2] ff 60 [2] b8 62 [2] ff 73 [2] b1 7f [2] bd 75 [2] aa 7e [2] b1 30 [2] 8c }

  condition:
    any of them
}