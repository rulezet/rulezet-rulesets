rule TTP_XOR_MULT_DOSStub_b3bf {
  strings:
    $key_b3bf = { e7 d7 [2] 93 cf [2] d4 cd [2] 93 dc [2] dd d0 [2] d1 da [2] c6 d1 [2] dd 9f [2] e0 }

  condition:
    any of them
}