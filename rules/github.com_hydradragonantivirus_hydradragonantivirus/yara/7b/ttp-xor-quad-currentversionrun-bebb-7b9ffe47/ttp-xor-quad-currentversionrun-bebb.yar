rule TTP_XOR_QUAD_CurrentVersionRun_bebb {
  strings:
    $key_bebb = { ed d4 [2] c9 da [2] e2 f6 [2] cc d4 [2] d8 cf [2] d7 d5 [2] c9 c8 [2] cb c9 [2] d0 cf [2] cc c8 [2] d0 e7 }

  condition:
    any of them
}