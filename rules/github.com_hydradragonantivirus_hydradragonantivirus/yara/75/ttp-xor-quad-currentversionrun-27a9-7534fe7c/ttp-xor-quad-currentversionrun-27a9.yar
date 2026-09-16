rule TTP_XOR_QUAD_CurrentVersionRun_27a9 {
  strings:
    $key_27a9 = { 74 c6 [2] 50 c8 [2] 7b e4 [2] 55 c6 [2] 41 dd [2] 4e c7 [2] 50 da [2] 52 db [2] 49 dd [2] 55 da [2] 49 f5 }

  condition:
    any of them
}