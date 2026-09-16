rule TTP_XOR_MULT_DOSStub_06bb {
  strings:
    $key_06bb = { 52 d3 [2] 26 cb [2] 61 c9 [2] 26 d8 [2] 68 d4 [2] 64 de [2] 73 d5 [2] 68 9b [2] 55 }

  condition:
    any of them
}