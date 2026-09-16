rule TTP_XOR_MULT_DOSStub_b0bf {
  strings:
    $key_b0bf = { e4 d7 [2] 90 cf [2] d7 cd [2] 90 dc [2] de d0 [2] d2 da [2] c5 d1 [2] de 9f [2] e3 }

  condition:
    any of them
}