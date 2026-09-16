rule TTP_XOR_QUAD_CurrentVersionRun_47a9 {
  strings:
    $key_47a9 = { 14 c6 [2] 30 c8 [2] 1b e4 [2] 35 c6 [2] 21 dd [2] 2e c7 [2] 30 da [2] 32 db [2] 29 dd [2] 35 da [2] 29 f5 }

  condition:
    any of them
}