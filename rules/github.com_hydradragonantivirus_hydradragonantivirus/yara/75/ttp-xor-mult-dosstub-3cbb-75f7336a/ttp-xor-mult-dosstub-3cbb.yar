rule TTP_XOR_MULT_DOSStub_3cbb {
  strings:
    $key_3cbb = { 68 d3 [2] 1c cb [2] 5b c9 [2] 1c d8 [2] 52 d4 [2] 5e de [2] 49 d5 [2] 52 9b [2] 6f }

  condition:
    any of them
}