rule TTP_XOR_QUAD_CurrentVersionRun_aaaa {
  strings:
    $key_aaaa = { f9 c5 [2] dd cb [2] f6 e7 [2] d8 c5 [2] cc de [2] c3 c4 [2] dd d9 [2] df d8 [2] c4 de [2] d8 d9 [2] c4 f6 }

  condition:
    any of them
}