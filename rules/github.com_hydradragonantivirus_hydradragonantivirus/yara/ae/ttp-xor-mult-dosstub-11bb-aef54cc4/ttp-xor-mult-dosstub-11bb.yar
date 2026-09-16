rule TTP_XOR_MULT_DOSStub_11bb {
  strings:
    $key_11bb = { 45 d3 [2] 31 cb [2] 76 c9 [2] 31 d8 [2] 7f d4 [2] 73 de [2] 64 d5 [2] 7f 9b [2] 42 }

  condition:
    any of them
}