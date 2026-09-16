rule TTP_XOR_QUAD_CurrentVersionRun_f0ae {
  strings:
    $key_f0ae = { a3 c1 [2] 87 cf [2] ac e3 [2] 82 c1 [2] 96 da [2] 99 c0 [2] 87 dd [2] 85 dc [2] 9e da [2] 82 dd [2] 9e f2 }

  condition:
    any of them
}