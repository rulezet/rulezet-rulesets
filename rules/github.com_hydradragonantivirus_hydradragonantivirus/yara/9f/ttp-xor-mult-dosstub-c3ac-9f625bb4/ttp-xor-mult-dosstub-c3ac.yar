rule TTP_XOR_MULT_DOSStub_c3ac {
  strings:
    $key_c3ac = { 97 c4 [2] e3 dc [2] a4 de [2] e3 cf [2] ad c3 [2] a1 c9 [2] b6 c2 [2] ad 8c [2] 90 }

  condition:
    any of them
}