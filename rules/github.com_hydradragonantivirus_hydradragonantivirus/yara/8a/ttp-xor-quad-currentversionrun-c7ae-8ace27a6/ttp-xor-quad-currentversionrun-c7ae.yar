rule TTP_XOR_QUAD_CurrentVersionRun_c7ae {
  strings:
    $key_c7ae = { 94 c1 [2] b0 cf [2] 9b e3 [2] b5 c1 [2] a1 da [2] ae c0 [2] b0 dd [2] b2 dc [2] a9 da [2] b5 dd [2] a9 f2 }

  condition:
    any of them
}