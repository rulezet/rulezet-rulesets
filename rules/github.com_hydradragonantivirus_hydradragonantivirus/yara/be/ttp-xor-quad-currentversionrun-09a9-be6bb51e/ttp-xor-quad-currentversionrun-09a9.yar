rule TTP_XOR_QUAD_CurrentVersionRun_09a9 {
  strings:
    $key_09a9 = { 5a c6 [2] 7e c8 [2] 55 e4 [2] 7b c6 [2] 6f dd [2] 60 c7 [2] 7e da [2] 7c db [2] 67 dd [2] 7b da [2] 67 f5 }

  condition:
    any of them
}