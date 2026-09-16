rule TTP_XOR_MULT_DOSStub_34ac {
  strings:
    $key_34ac = { 60 c4 [2] 14 dc [2] 53 de [2] 14 cf [2] 5a c3 [2] 56 c9 [2] 41 c2 [2] 5a 8c [2] 67 }

  condition:
    any of them
}