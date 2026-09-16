rule TTP_XOR_QUAD_CurrentVersionRun_d2f7 {
  strings:
    $key_d2f7 = { 81 98 [2] a5 96 [2] 8e ba [2] a0 98 [2] b4 83 [2] bb 99 [2] a5 84 [2] a7 85 [2] bc 83 [2] a0 84 [2] bc ab }

  condition:
    any of them
}