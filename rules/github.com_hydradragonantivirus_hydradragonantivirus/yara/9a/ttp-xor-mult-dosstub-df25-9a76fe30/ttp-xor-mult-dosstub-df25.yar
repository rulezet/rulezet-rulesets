rule TTP_XOR_MULT_DOSStub_df25 {
  strings:
    $key_df25 = { 8b 4d [2] ff 55 [2] b8 57 [2] ff 46 [2] b1 4a [2] bd 40 [2] aa 4b [2] b1 05 [2] 8c }

  condition:
    any of them
}