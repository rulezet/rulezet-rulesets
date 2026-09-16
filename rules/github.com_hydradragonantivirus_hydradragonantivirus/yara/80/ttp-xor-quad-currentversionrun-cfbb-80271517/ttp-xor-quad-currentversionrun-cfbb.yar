rule TTP_XOR_QUAD_CurrentVersionRun_cfbb {
  strings:
    $key_cfbb = { 9c d4 [2] b8 da [2] 93 f6 [2] bd d4 [2] a9 cf [2] a6 d5 [2] b8 c8 [2] ba c9 [2] a1 cf [2] bd c8 [2] a1 e7 }

  condition:
    any of them
}