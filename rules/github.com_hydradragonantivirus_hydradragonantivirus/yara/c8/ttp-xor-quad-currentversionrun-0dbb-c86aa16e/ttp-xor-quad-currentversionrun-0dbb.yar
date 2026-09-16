rule TTP_XOR_QUAD_CurrentVersionRun_0dbb {
  strings:
    $key_0dbb = { 5e d4 [2] 7a da [2] 51 f6 [2] 7f d4 [2] 6b cf [2] 64 d5 [2] 7a c8 [2] 78 c9 [2] 63 cf [2] 7f c8 [2] 63 e7 }

  condition:
    any of them
}