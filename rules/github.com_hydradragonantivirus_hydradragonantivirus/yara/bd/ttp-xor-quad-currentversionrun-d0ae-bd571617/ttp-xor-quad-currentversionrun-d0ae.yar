rule TTP_XOR_QUAD_CurrentVersionRun_d0ae {
  strings:
    $key_d0ae = { 83 c1 [2] a7 cf [2] 8c e3 [2] a2 c1 [2] b6 da [2] b9 c0 [2] a7 dd [2] a5 dc [2] be da [2] a2 dd [2] be f2 }

  condition:
    any of them
}