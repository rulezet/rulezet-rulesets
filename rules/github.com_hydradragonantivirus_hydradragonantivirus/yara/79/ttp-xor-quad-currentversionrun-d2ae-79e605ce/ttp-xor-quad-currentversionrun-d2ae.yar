rule TTP_XOR_QUAD_CurrentVersionRun_d2ae {
  strings:
    $key_d2ae = { 81 c1 [2] a5 cf [2] 8e e3 [2] a0 c1 [2] b4 da [2] bb c0 [2] a5 dd [2] a7 dc [2] bc da [2] a0 dd [2] bc f2 }

  condition:
    any of them
}