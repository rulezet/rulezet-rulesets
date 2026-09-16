rule TTP_XOR_MULT_DOSStub_49ba {
  strings:
    $key_49ba = { 1d d2 [2] 69 ca [2] 2e c8 [2] 69 d9 [2] 27 d5 [2] 2b df [2] 3c d4 [2] 27 9a [2] 1a }

  condition:
    any of them
}