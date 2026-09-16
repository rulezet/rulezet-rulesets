rule TTP_XOR_QUAD_CurrentVersionRun_49a9 {
  strings:
    $key_49a9 = { 1a c6 [2] 3e c8 [2] 15 e4 [2] 3b c6 [2] 2f dd [2] 20 c7 [2] 3e da [2] 3c db [2] 27 dd [2] 3b da [2] 27 f5 }

  condition:
    any of them
}