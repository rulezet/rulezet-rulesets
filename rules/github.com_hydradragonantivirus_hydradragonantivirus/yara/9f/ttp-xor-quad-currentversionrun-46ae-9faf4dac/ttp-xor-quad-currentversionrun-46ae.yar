rule TTP_XOR_QUAD_CurrentVersionRun_46ae {
  strings:
    $key_46ae = { 15 c1 [2] 31 cf [2] 1a e3 [2] 34 c1 [2] 20 da [2] 2f c0 [2] 31 dd [2] 33 dc [2] 28 da [2] 34 dd [2] 28 f2 }

  condition:
    any of them
}