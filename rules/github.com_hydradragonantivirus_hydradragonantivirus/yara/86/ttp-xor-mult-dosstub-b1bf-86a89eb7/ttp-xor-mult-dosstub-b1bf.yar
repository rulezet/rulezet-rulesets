rule TTP_XOR_MULT_DOSStub_b1bf {
  strings:
    $key_b1bf = { e5 d7 [2] 91 cf [2] d6 cd [2] 91 dc [2] df d0 [2] d3 da [2] c4 d1 [2] df 9f [2] e2 }

  condition:
    any of them
}