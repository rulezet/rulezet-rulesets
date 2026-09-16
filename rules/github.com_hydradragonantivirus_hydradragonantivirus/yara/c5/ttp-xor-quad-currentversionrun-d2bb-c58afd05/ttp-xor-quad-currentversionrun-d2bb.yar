rule TTP_XOR_QUAD_CurrentVersionRun_d2bb {
  strings:
    $key_d2bb = { 81 d4 [2] a5 da [2] 8e f6 [2] a0 d4 [2] b4 cf [2] bb d5 [2] a5 c8 [2] a7 c9 [2] bc cf [2] a0 c8 [2] bc e7 }

  condition:
    any of them
}