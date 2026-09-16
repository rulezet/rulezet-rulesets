rule TTP_XOR_QUAD_CurrentVersionRun_acaa {
  strings:
    $key_acaa = { ff c5 [2] db cb [2] f0 e7 [2] de c5 [2] ca de [2] c5 c4 [2] db d9 [2] d9 d8 [2] c2 de [2] de d9 [2] c2 f6 }

  condition:
    any of them
}