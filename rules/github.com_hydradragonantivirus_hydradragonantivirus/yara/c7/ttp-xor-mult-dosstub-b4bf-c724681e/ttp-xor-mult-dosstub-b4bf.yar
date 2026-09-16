rule TTP_XOR_MULT_DOSStub_b4bf {
  strings:
    $key_b4bf = { e0 d7 [2] 94 cf [2] d3 cd [2] 94 dc [2] da d0 [2] d6 da [2] c1 d1 [2] da 9f [2] e7 }

  condition:
    any of them
}