rule TTP_XOR_MULT_DOSStub_df4c {
  strings:
    $key_df4c = { 8b 24 [2] ff 3c [2] b8 3e [2] ff 2f [2] b1 23 [2] bd 29 [2] aa 22 [2] b1 6c [2] 8c }

  condition:
    any of them
}