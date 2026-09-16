rule TTP_XOR_MULT_DOSStub_68ba {
  strings:
    $key_68ba = { 3c d2 [2] 48 ca [2] 0f c8 [2] 48 d9 [2] 06 d5 [2] 0a df [2] 1d d4 [2] 06 9a [2] 3b }

  condition:
    any of them
}