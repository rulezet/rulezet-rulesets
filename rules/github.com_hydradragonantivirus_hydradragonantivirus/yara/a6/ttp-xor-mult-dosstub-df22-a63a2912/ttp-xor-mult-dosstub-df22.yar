rule TTP_XOR_MULT_DOSStub_df22 {
  strings:
    $key_df22 = { 8b 4a [2] ff 52 [2] b8 50 [2] ff 41 [2] b1 4d [2] bd 47 [2] aa 4c [2] b1 02 [2] 8c }

  condition:
    any of them
}