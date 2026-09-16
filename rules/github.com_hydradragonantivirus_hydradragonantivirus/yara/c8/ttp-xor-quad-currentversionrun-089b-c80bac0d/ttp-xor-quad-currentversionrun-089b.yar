rule TTP_XOR_QUAD_CurrentVersionRun_089b {
  strings:
    $key_089b = { 5b f4 [2] 7f fa [2] 54 d6 [2] 7a f4 [2] 6e ef [2] 61 f5 [2] 7f e8 [2] 7d e9 [2] 66 ef [2] 7a e8 [2] 66 c7 }

  condition:
    any of them
}