rule TTP_XOR_MULT_DOSStub_df39 {
  strings:
    $key_df39 = { 8b 51 [2] ff 49 [2] b8 4b [2] ff 5a [2] b1 56 [2] bd 5c [2] aa 57 [2] b1 19 [2] 8c }

  condition:
    any of them
}