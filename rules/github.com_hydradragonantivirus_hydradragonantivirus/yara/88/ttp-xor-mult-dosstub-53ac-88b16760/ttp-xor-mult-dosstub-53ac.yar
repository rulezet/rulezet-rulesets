rule TTP_XOR_MULT_DOSStub_53ac {
  strings:
    $key_53ac = { 07 c4 [2] 73 dc [2] 34 de [2] 73 cf [2] 3d c3 [2] 31 c9 [2] 26 c2 [2] 3d 8c [2] 00 }

  condition:
    any of them
}