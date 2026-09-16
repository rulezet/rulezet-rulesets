rule TTP_XOR_MULT_DOSStub_57bb {
  strings:
    $key_57bb = { 03 d3 [2] 77 cb [2] 30 c9 [2] 77 d8 [2] 39 d4 [2] 35 de [2] 22 d5 [2] 39 9b [2] 04 }

  condition:
    any of them
}