rule TTP_XOR_QUAD_CurrentVersionRun_3ca9 {
  strings:
    $key_3ca9 = { 6f c6 [2] 4b c8 [2] 60 e4 [2] 4e c6 [2] 5a dd [2] 55 c7 [2] 4b da [2] 49 db [2] 52 dd [2] 4e da [2] 52 f5 }

  condition:
    any of them
}