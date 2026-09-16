rule TTP_XOR_QUAD_CurrentVersionRun_2dbb {
  strings:
    $key_2dbb = { 7e d4 [2] 5a da [2] 71 f6 [2] 5f d4 [2] 4b cf [2] 44 d5 [2] 5a c8 [2] 58 c9 [2] 43 cf [2] 5f c8 [2] 43 e7 }

  condition:
    any of them
}