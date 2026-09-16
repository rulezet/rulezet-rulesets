rule TTP_XOR_MULT_DOSStub_df23 {
  strings:
    $key_df23 = { 8b 4b [2] ff 53 [2] b8 51 [2] ff 40 [2] b1 4c [2] bd 46 [2] aa 4d [2] b1 03 [2] 8c }

  condition:
    any of them
}