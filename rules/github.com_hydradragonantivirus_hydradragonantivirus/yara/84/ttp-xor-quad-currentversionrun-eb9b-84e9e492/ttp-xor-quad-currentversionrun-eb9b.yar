rule TTP_XOR_QUAD_CurrentVersionRun_eb9b {
  strings:
    $key_eb9b = { b8 f4 [2] 9c fa [2] b7 d6 [2] 99 f4 [2] 8d ef [2] 82 f5 [2] 9c e8 [2] 9e e9 [2] 85 ef [2] 99 e8 [2] 85 c7 }

  condition:
    any of them
}