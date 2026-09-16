rule TTP_XOR_QUAD_CurrentVersionRun_789b {
  strings:
    $key_789b = { 2b f4 [2] 0f fa [2] 24 d6 [2] 0a f4 [2] 1e ef [2] 11 f5 [2] 0f e8 [2] 0d e9 [2] 16 ef [2] 0a e8 [2] 16 c7 }

  condition:
    any of them
}