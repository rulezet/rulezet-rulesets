rule TTP_XOR_QUAD_CurrentVersionRun_eca9 {
  strings:
    $key_eca9 = { bf c6 [2] 9b c8 [2] b0 e4 [2] 9e c6 [2] 8a dd [2] 85 c7 [2] 9b da [2] 99 db [2] 82 dd [2] 9e da [2] 82 f5 }

  condition:
    any of them
}