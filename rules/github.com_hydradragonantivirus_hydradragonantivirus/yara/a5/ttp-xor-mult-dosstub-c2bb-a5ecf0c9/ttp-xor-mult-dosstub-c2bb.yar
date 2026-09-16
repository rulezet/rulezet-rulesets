rule TTP_XOR_MULT_DOSStub_c2bb {
  strings:
    $key_c2bb = { 96 d3 [2] e2 cb [2] a5 c9 [2] e2 d8 [2] ac d4 [2] a0 de [2] b7 d5 [2] ac 9b [2] 91 }

  condition:
    any of them
}