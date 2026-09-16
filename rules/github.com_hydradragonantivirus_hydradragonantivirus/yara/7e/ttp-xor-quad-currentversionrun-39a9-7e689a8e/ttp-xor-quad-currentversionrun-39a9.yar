rule TTP_XOR_QUAD_CurrentVersionRun_39a9 {
  strings:
    $key_39a9 = { 6a c6 [2] 4e c8 [2] 65 e4 [2] 4b c6 [2] 5f dd [2] 50 c7 [2] 4e da [2] 4c db [2] 57 dd [2] 4b da [2] 57 f5 }

  condition:
    any of them
}