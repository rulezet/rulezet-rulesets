rule TTP_XOR_QUAD_CurrentVersionRun_199b {
  strings:
    $key_199b = { 4a f4 [2] 6e fa [2] 45 d6 [2] 6b f4 [2] 7f ef [2] 70 f5 [2] 6e e8 [2] 6c e9 [2] 77 ef [2] 6b e8 [2] 77 c7 }

  condition:
    any of them
}