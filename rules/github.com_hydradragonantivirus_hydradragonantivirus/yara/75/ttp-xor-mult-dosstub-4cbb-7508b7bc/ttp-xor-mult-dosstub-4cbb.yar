rule TTP_XOR_MULT_DOSStub_4cbb {
  strings:
    $key_4cbb = { 18 d3 [2] 6c cb [2] 2b c9 [2] 6c d8 [2] 22 d4 [2] 2e de [2] 39 d5 [2] 22 9b [2] 1f }

  condition:
    any of them
}