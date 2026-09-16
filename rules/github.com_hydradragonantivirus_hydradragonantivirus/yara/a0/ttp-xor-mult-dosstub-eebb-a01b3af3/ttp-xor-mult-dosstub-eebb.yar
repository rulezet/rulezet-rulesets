rule TTP_XOR_MULT_DOSStub_eebb {
  strings:
    $key_eebb = { ba d3 [2] ce cb [2] 89 c9 [2] ce d8 [2] 80 d4 [2] 8c de [2] 9b d5 [2] 80 9b [2] bd }

  condition:
    any of them
}