rule TTP_XOR_MULT_DOSStub_05bb {
  strings:
    $key_05bb = { 51 d3 [2] 25 cb [2] 62 c9 [2] 25 d8 [2] 6b d4 [2] 67 de [2] 70 d5 [2] 6b 9b [2] 56 }

  condition:
    any of them
}