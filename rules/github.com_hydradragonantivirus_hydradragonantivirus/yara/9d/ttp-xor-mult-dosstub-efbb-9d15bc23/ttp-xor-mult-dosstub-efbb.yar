rule TTP_XOR_MULT_DOSStub_efbb {
  strings:
    $key_efbb = { bb d3 [2] cf cb [2] 88 c9 [2] cf d8 [2] 81 d4 [2] 8d de [2] 9a d5 [2] 81 9b [2] bc }

  condition:
    any of them
}