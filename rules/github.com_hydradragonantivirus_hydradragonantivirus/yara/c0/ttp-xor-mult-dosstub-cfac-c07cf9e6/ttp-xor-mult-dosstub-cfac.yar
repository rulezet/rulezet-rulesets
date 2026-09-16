rule TTP_XOR_MULT_DOSStub_cfac {
  strings:
    $key_cfac = { 9b c4 [2] ef dc [2] a8 de [2] ef cf [2] a1 c3 [2] ad c9 [2] ba c2 [2] a1 8c [2] 9c }

  condition:
    any of them
}