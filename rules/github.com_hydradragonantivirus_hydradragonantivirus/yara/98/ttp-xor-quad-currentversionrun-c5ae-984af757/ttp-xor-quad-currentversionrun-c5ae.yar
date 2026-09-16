rule TTP_XOR_QUAD_CurrentVersionRun_c5ae {
  strings:
    $key_c5ae = { 96 c1 [2] b2 cf [2] 99 e3 [2] b7 c1 [2] a3 da [2] ac c0 [2] b2 dd [2] b0 dc [2] ab da [2] b7 dd [2] ab f2 }

  condition:
    any of them
}