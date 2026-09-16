rule TTP_XOR_QUAD_CurrentVersionRun_66ae {
  strings:
    $key_66ae = { 35 c1 [2] 11 cf [2] 3a e3 [2] 14 c1 [2] 00 da [2] 0f c0 [2] 11 dd [2] 13 dc [2] 08 da [2] 14 dd [2] 08 f2 }

  condition:
    any of them
}