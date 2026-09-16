rule TTP_XOR_QUAD_CurrentVersionRun_a5a9 {
  strings:
    $key_a5a9 = { f6 c6 [2] d2 c8 [2] f9 e4 [2] d7 c6 [2] c3 dd [2] cc c7 [2] d2 da [2] d0 db [2] cb dd [2] d7 da [2] cb f5 }

  condition:
    any of them
}