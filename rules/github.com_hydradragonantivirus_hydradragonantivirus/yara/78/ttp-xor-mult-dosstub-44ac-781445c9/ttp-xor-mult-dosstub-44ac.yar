rule TTP_XOR_MULT_DOSStub_44ac {
  strings:
    $key_44ac = { 10 c4 [2] 64 dc [2] 23 de [2] 64 cf [2] 2a c3 [2] 26 c9 [2] 31 c2 [2] 2a 8c [2] 17 }

  condition:
    any of them
}