rule TTP_XOR_QUAD_CurrentVersionRun_399b {
  strings:
    $key_399b = { 6a f4 [2] 4e fa [2] 65 d6 [2] 4b f4 [2] 5f ef [2] 50 f5 [2] 4e e8 [2] 4c e9 [2] 57 ef [2] 4b e8 [2] 57 c7 }

  condition:
    any of them
}