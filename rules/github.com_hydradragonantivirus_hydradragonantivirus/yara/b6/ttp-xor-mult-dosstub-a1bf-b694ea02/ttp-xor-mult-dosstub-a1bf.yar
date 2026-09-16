rule TTP_XOR_MULT_DOSStub_a1bf {
  strings:
    $key_a1bf = { f5 d7 [2] 81 cf [2] c6 cd [2] 81 dc [2] cf d0 [2] c3 da [2] d4 d1 [2] cf 9f [2] f2 }

  condition:
    any of them
}