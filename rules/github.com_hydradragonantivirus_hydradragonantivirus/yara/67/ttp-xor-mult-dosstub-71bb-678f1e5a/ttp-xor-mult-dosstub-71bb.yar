rule TTP_XOR_MULT_DOSStub_71bb {
  strings:
    $key_71bb = { 25 d3 [2] 51 cb [2] 16 c9 [2] 51 d8 [2] 1f d4 [2] 13 de [2] 04 d5 [2] 1f 9b [2] 22 }

  condition:
    any of them
}