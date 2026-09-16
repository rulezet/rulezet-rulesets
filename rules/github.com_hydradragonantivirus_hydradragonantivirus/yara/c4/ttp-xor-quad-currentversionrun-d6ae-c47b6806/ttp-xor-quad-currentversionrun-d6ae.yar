rule TTP_XOR_QUAD_CurrentVersionRun_d6ae {
  strings:
    $key_d6ae = { 85 c1 [2] a1 cf [2] 8a e3 [2] a4 c1 [2] b0 da [2] bf c0 [2] a1 dd [2] a3 dc [2] b8 da [2] a4 dd [2] b8 f2 }

  condition:
    any of them
}