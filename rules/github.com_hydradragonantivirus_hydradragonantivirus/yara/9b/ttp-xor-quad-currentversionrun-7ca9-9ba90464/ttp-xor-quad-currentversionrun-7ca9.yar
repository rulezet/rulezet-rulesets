rule TTP_XOR_QUAD_CurrentVersionRun_7ca9 {
  strings:
    $key_7ca9 = { 2f c6 [2] 0b c8 [2] 20 e4 [2] 0e c6 [2] 1a dd [2] 15 c7 [2] 0b da [2] 09 db [2] 12 dd [2] 0e da [2] 12 f5 }

  condition:
    any of them
}