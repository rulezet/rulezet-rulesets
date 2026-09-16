rule TTP_XOR_QUAD_CurrentVersionRun_37a9 {
  strings:
    $key_37a9 = { 64 c6 [2] 40 c8 [2] 6b e4 [2] 45 c6 [2] 51 dd [2] 5e c7 [2] 40 da [2] 42 db [2] 59 dd [2] 45 da [2] 59 f5 }

  condition:
    any of them
}