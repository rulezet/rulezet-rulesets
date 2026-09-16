rule TTP_XOR_MULT_DOSStub_df64 {
  strings:
    $key_df64 = { 8b 0c [2] ff 14 [2] b8 16 [2] ff 07 [2] b1 0b [2] bd 01 [2] aa 0a [2] b1 44 [2] 8c }

  condition:
    any of them
}