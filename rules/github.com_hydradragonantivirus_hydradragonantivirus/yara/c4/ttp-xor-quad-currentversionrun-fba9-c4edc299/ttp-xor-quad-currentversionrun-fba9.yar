rule TTP_XOR_QUAD_CurrentVersionRun_fba9 {
  strings:
    $key_fba9 = { a8 c6 [2] 8c c8 [2] a7 e4 [2] 89 c6 [2] 9d dd [2] 92 c7 [2] 8c da [2] 8e db [2] 95 dd [2] 89 da [2] 95 f5 }

  condition:
    any of them
}