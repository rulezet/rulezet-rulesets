rule TTP_XOR_MULT_DOSStub_df11 {
  strings:
    $key_df11 = { 8b 79 [2] ff 61 [2] b8 63 [2] ff 72 [2] b1 7e [2] bd 74 [2] aa 7f [2] b1 31 [2] 8c }

  condition:
    any of them
}