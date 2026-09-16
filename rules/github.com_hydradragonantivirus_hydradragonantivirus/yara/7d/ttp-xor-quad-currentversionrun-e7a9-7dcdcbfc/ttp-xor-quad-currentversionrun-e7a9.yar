rule TTP_XOR_QUAD_CurrentVersionRun_e7a9 {
  strings:
    $key_e7a9 = { b4 c6 [2] 90 c8 [2] bb e4 [2] 95 c6 [2] 81 dd [2] 8e c7 [2] 90 da [2] 92 db [2] 89 dd [2] 95 da [2] 89 f5 }

  condition:
    any of them
}