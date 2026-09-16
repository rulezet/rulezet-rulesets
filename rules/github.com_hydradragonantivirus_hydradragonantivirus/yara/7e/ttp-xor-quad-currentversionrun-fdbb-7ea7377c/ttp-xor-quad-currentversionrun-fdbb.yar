rule TTP_XOR_QUAD_CurrentVersionRun_fdbb {
  strings:
    $key_fdbb = { ae d4 [2] 8a da [2] a1 f6 [2] 8f d4 [2] 9b cf [2] 94 d5 [2] 8a c8 [2] 88 c9 [2] 93 cf [2] 8f c8 [2] 93 e7 }

  condition:
    any of them
}