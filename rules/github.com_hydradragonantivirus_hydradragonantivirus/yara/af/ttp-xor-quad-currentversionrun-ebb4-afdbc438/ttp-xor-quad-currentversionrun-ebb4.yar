rule TTP_XOR_QUAD_CurrentVersionRun_ebb4 {
  strings:
    $key_ebb4 = { b8 db [2] 9c d5 [2] b7 f9 [2] 99 db [2] 8d c0 [2] 82 da [2] 9c c7 [2] 9e c6 [2] 85 c0 [2] 99 c7 [2] 85 e8 }

  condition:
    any of them
}