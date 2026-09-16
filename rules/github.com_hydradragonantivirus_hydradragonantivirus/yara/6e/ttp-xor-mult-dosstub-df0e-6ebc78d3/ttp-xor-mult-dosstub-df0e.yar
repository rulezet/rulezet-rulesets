rule TTP_XOR_MULT_DOSStub_df0e {
  strings:
    $key_df0e = { 8b 66 [2] ff 7e [2] b8 7c [2] ff 6d [2] b1 61 [2] bd 6b [2] aa 60 [2] b1 2e [2] 8c }

  condition:
    any of them
}