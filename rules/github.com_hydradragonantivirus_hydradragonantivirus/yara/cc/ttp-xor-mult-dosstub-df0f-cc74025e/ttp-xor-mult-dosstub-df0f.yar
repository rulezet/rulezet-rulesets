rule TTP_XOR_MULT_DOSStub_df0f {
  strings:
    $key_df0f = { 8b 67 [2] ff 7f [2] b8 7d [2] ff 6c [2] b1 60 [2] bd 6a [2] aa 61 [2] b1 2f [2] 8c }

  condition:
    any of them
}