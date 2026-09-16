rule TTP_XOR_QUAD_CurrentVersionRun_eba4 {
  strings:
    $key_eba4 = { b8 cb [2] 9c c5 [2] b7 e9 [2] 99 cb [2] 8d d0 [2] 82 ca [2] 9c d7 [2] 9e d6 [2] 85 d0 [2] 99 d7 [2] 85 f8 }

  condition:
    any of them
}