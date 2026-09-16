rule TTP_XOR_QUAD_CurrentVersionRun_05bb {
  strings:
    $key_05bb = { 56 d4 [2] 72 da [2] 59 f6 [2] 77 d4 [2] 63 cf [2] 6c d5 [2] 72 c8 [2] 70 c9 [2] 6b cf [2] 77 c8 [2] 6b e7 }

  condition:
    any of them
}