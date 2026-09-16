rule TTP_XOR_MULT_DOSStub_08ba {
  strings:
    $key_08ba = { 5c d2 [2] 28 ca [2] 6f c8 [2] 28 d9 [2] 66 d5 [2] 6a df [2] 7d d4 [2] 66 9a [2] 5b }

  condition:
    any of them
}