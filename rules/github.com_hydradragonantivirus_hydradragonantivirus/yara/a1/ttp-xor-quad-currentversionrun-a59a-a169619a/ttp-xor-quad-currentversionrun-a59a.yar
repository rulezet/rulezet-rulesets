rule TTP_XOR_QUAD_CurrentVersionRun_a59a {
  strings:
    $key_a59a = { f6 f5 [2] d2 fb [2] f9 d7 [2] d7 f5 [2] c3 ee [2] cc f4 [2] d2 e9 [2] d0 e8 [2] cb ee [2] d7 e9 [2] cb c6 }

  condition:
    any of them
}