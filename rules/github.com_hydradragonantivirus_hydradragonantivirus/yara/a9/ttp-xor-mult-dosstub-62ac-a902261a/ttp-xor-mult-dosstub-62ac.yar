rule TTP_XOR_MULT_DOSStub_62ac {
  strings:
    $key_62ac = { 36 c4 [2] 42 dc [2] 05 de [2] 42 cf [2] 0c c3 [2] 00 c9 [2] 17 c2 [2] 0c 8c [2] 31 }

  condition:
    any of them
}