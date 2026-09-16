rule TTP_XOR_QUAD_CurrentVersionRun_eebb {
  strings:
    $key_eebb = { bd d4 [2] 99 da [2] b2 f6 [2] 9c d4 [2] 88 cf [2] 87 d5 [2] 99 c8 [2] 9b c9 [2] 80 cf [2] 9c c8 [2] 80 e7 }

  condition:
    any of them
}