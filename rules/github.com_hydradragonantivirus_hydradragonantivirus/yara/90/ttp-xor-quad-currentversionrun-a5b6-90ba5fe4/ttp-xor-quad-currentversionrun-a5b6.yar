rule TTP_XOR_QUAD_CurrentVersionRun_a5b6 {
  strings:
    $key_a5b6 = { f6 d9 [2] d2 d7 [2] f9 fb [2] d7 d9 [2] c3 c2 [2] cc d8 [2] d2 c5 [2] d0 c4 [2] cb c2 [2] d7 c5 [2] cb ea }

  condition:
    any of them
}