rule TTP_XOR_QUAD_CurrentVersionRun_69a9 {
  strings:
    $key_69a9 = { 3a c6 [2] 1e c8 [2] 35 e4 [2] 1b c6 [2] 0f dd [2] 00 c7 [2] 1e da [2] 1c db [2] 07 dd [2] 1b da [2] 07 f5 }

  condition:
    any of them
}