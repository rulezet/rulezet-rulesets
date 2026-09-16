rule TTP_XOR_QUAD_CurrentVersionRun_f5a9 {
  strings:
    $key_f5a9 = { a6 c6 [2] 82 c8 [2] a9 e4 [2] 87 c6 [2] 93 dd [2] 9c c7 [2] 82 da [2] 80 db [2] 9b dd [2] 87 da [2] 9b f5 }

  condition:
    any of them
}