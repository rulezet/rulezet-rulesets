rule TTP_XOR_QUAD_CurrentVersionRun_f09b {
  strings:
    $key_f09b = { a3 f4 [2] 87 fa [2] ac d6 [2] 82 f4 [2] 96 ef [2] 99 f5 [2] 87 e8 [2] 85 e9 [2] 9e ef [2] 82 e8 [2] 9e c7 }

  condition:
    any of them
}