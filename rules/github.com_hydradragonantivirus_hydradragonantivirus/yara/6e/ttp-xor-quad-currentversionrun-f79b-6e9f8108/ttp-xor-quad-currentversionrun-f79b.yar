rule TTP_XOR_QUAD_CurrentVersionRun_f79b {
  strings:
    $key_f79b = { a4 f4 [2] 80 fa [2] ab d6 [2] 85 f4 [2] 91 ef [2] 9e f5 [2] 80 e8 [2] 82 e9 [2] 99 ef [2] 85 e8 [2] 99 c7 }

  condition:
    any of them
}