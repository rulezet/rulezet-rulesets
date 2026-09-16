rule TTP_XOR_QUAD_CurrentVersionRun_299b {
  strings:
    $key_299b = { 7a f4 [2] 5e fa [2] 75 d6 [2] 5b f4 [2] 4f ef [2] 40 f5 [2] 5e e8 [2] 5c e9 [2] 47 ef [2] 5b e8 [2] 47 c7 }

  condition:
    any of them
}