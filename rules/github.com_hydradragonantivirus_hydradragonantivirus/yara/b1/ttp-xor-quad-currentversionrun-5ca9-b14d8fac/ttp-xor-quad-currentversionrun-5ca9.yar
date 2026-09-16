rule TTP_XOR_QUAD_CurrentVersionRun_5ca9 {
  strings:
    $key_5ca9 = { 0f c6 [2] 2b c8 [2] 00 e4 [2] 2e c6 [2] 3a dd [2] 35 c7 [2] 2b da [2] 29 db [2] 32 dd [2] 2e da [2] 32 f5 }

  condition:
    any of them
}