rule TTP_XOR_QUAD_CurrentVersionRun_26ae {
  strings:
    $key_26ae = { 75 c1 [2] 51 cf [2] 7a e3 [2] 54 c1 [2] 40 da [2] 4f c0 [2] 51 dd [2] 53 dc [2] 48 da [2] 54 dd [2] 48 f2 }

  condition:
    any of them
}