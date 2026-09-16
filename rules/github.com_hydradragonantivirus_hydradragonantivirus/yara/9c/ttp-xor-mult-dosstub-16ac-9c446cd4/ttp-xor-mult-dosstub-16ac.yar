rule TTP_XOR_MULT_DOSStub_16ac {
  strings:
    $key_16ac = { 42 c4 [2] 36 dc [2] 71 de [2] 36 cf [2] 78 c3 [2] 74 c9 [2] 63 c2 [2] 78 8c [2] 45 }

  condition:
    any of them
}