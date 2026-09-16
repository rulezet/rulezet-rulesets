rule TTP_XOR_MULT_DOSStub_b6bd {
  strings:
    $key_b6bd = { e2 d5 [2] 96 cd [2] d1 cf [2] 96 de [2] d8 d2 [2] d4 d8 [2] c3 d3 [2] d8 9d [2] e5 }

  condition:
    any of them
}