rule TTP_XOR_QUAD_CurrentVersionRun_c1ae {
  strings:
    $key_c1ae = { 92 c1 [2] b6 cf [2] 9d e3 [2] b3 c1 [2] a7 da [2] a8 c0 [2] b6 dd [2] b4 dc [2] af da [2] b3 dd [2] af f2 }

  condition:
    any of them
}