rule TTP_XOR_QUAD_CurrentVersionRun_77a9 {
  strings:
    $key_77a9 = { 24 c6 [2] 00 c8 [2] 2b e4 [2] 05 c6 [2] 11 dd [2] 1e c7 [2] 00 da [2] 02 db [2] 19 dd [2] 05 da [2] 19 f5 }

  condition:
    any of them
}