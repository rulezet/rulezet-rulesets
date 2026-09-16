rule TTP_XOR_MULT_DOSStub_e0bf {
  strings:
    $key_e0bf = { b4 d7 [2] c0 cf [2] 87 cd [2] c0 dc [2] 8e d0 [2] 82 da [2] 95 d1 [2] 8e 9f [2] b3 }

  condition:
    any of them
}