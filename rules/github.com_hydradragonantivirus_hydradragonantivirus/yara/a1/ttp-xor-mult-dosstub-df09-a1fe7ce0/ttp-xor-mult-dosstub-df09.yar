rule TTP_XOR_MULT_DOSStub_df09 {
  strings:
    $key_df09 = { 8b 61 [2] ff 79 [2] b8 7b [2] ff 6a [2] b1 66 [2] bd 6c [2] aa 67 [2] b1 29 [2] 8c }

  condition:
    any of them
}