rule TTP_XOR_QUAD_CurrentVersionRun_289b {
  strings:
    $key_289b = { 7b f4 [2] 5f fa [2] 74 d6 [2] 5a f4 [2] 4e ef [2] 41 f5 [2] 5f e8 [2] 5d e9 [2] 46 ef [2] 5a e8 [2] 46 c7 }

  condition:
    any of them
}