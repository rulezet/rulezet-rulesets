rule TTP_XOR_QUAD_CurrentVersionRun_17a9 {
  strings:
    $key_17a9 = { 44 c6 [2] 60 c8 [2] 4b e4 [2] 65 c6 [2] 71 dd [2] 7e c7 [2] 60 da [2] 62 db [2] 79 dd [2] 65 da [2] 79 f5 }

  condition:
    any of them
}