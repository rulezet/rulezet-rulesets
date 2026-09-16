rule TTP_XOR_MULT_DOSStub_76bb {
  strings:
    $key_76bb = { 22 d3 [2] 56 cb [2] 11 c9 [2] 56 d8 [2] 18 d4 [2] 14 de [2] 03 d5 [2] 18 9b [2] 25 }

  condition:
    any of them
}