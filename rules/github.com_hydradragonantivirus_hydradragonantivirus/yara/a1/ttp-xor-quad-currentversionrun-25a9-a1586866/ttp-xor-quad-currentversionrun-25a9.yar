rule TTP_XOR_QUAD_CurrentVersionRun_25a9 {
  strings:
    $key_25a9 = { 76 c6 [2] 52 c8 [2] 79 e4 [2] 57 c6 [2] 43 dd [2] 4c c7 [2] 52 da [2] 50 db [2] 4b dd [2] 57 da [2] 4b f5 }

  condition:
    any of them
}