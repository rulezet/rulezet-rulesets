rule TTP_XOR_QUAD_CurrentVersionRun_d1ae {
  strings:
    $key_d1ae = { 82 c1 [2] a6 cf [2] 8d e3 [2] a3 c1 [2] b7 da [2] b8 c0 [2] a6 dd [2] a4 dc [2] bf da [2] a3 dd [2] bf f2 }

  condition:
    any of them
}