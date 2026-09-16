rule TTP_XOR_QUAD_CurrentVersionRun_41ae {
  strings:
    $key_41ae = { 12 c1 [2] 36 cf [2] 1d e3 [2] 33 c1 [2] 27 da [2] 28 c0 [2] 36 dd [2] 34 dc [2] 2f da [2] 33 dd [2] 2f f2 }

  condition:
    any of them
}