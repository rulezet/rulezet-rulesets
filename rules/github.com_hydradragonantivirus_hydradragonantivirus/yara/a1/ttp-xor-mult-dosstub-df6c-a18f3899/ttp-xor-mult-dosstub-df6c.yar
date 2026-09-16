rule TTP_XOR_MULT_DOSStub_df6c {
  strings:
    $key_df6c = { 8b 04 [2] ff 1c [2] b8 1e [2] ff 0f [2] b1 03 [2] bd 09 [2] aa 02 [2] b1 4c [2] 8c }

  condition:
    any of them
}