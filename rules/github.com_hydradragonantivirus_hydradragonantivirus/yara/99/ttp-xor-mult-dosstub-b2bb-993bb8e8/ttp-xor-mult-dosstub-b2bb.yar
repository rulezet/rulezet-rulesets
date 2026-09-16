rule TTP_XOR_MULT_DOSStub_b2bb {
  strings:
    $key_b2bb = { e6 d3 [2] 92 cb [2] d5 c9 [2] 92 d8 [2] dc d4 [2] d0 de [2] c7 d5 [2] dc 9b [2] e1 }

  condition:
    any of them
}