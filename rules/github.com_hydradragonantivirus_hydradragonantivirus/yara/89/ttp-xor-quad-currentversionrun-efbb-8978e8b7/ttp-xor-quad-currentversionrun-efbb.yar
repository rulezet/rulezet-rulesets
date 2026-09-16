rule TTP_XOR_QUAD_CurrentVersionRun_efbb {
  strings:
    $key_efbb = { bc d4 [2] 98 da [2] b3 f6 [2] 9d d4 [2] 89 cf [2] 86 d5 [2] 98 c8 [2] 9a c9 [2] 81 cf [2] 9d c8 [2] 81 e7 }

  condition:
    any of them
}