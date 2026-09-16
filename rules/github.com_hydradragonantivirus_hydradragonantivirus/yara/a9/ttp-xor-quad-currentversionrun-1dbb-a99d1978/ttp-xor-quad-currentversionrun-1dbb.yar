rule TTP_XOR_QUAD_CurrentVersionRun_1dbb {
  strings:
    $key_1dbb = { 4e d4 [2] 6a da [2] 41 f6 [2] 6f d4 [2] 7b cf [2] 74 d5 [2] 6a c8 [2] 68 c9 [2] 73 cf [2] 6f c8 [2] 73 e7 }

  condition:
    any of them
}