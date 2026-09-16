rule TTP_XOR_QUAD_CurrentVersionRun_1ca9 {
  strings:
    $key_1ca9 = { 4f c6 [2] 6b c8 [2] 40 e4 [2] 6e c6 [2] 7a dd [2] 75 c7 [2] 6b da [2] 69 db [2] 72 dd [2] 6e da [2] 72 f5 }

  condition:
    any of them
}