rule TTP_XOR_MULT_DOSStub_49bc {
  strings:
    $key_49bc = { 1d d4 [2] 69 cc [2] 2e ce [2] 69 df [2] 27 d3 [2] 2b d9 [2] 3c d2 [2] 27 9c [2] 1a }

  condition:
    any of them
}