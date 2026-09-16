rule TTP_XOR_QUAD_CurrentVersionRun_fea9 {
  strings:
    $key_fea9 = { ad c6 [2] 89 c8 [2] a2 e4 [2] 8c c6 [2] 98 dd [2] 97 c7 [2] 89 da [2] 8b db [2] 90 dd [2] 8c da [2] 90 f5 }

  condition:
    any of them
}