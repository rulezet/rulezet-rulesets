rule TTP_XOR_QUAD_CurrentVersionRun_e9a9 {
  strings:
    $key_e9a9 = { ba c6 [2] 9e c8 [2] b5 e4 [2] 9b c6 [2] 8f dd [2] 80 c7 [2] 9e da [2] 9c db [2] 87 dd [2] 9b da [2] 87 f5 }

  condition:
    any of them
}