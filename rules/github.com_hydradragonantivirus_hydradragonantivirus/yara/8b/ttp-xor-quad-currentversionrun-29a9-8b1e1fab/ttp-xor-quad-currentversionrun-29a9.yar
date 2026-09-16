rule TTP_XOR_QUAD_CurrentVersionRun_29a9 {
  strings:
    $key_29a9 = { 7a c6 [2] 5e c8 [2] 75 e4 [2] 5b c6 [2] 4f dd [2] 40 c7 [2] 5e da [2] 5c db [2] 47 dd [2] 5b da [2] 47 f5 }

  condition:
    any of them
}