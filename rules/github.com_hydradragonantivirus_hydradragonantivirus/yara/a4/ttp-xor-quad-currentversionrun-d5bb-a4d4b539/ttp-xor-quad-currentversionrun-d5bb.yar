rule TTP_XOR_QUAD_CurrentVersionRun_d5bb {
  strings:
    $key_d5bb = { 86 d4 [2] a2 da [2] 89 f6 [2] a7 d4 [2] b3 cf [2] bc d5 [2] a2 c8 [2] a0 c9 [2] bb cf [2] a7 c8 [2] bb e7 }

  condition:
    any of them
}