rule TTP_XOR_QUAD_CurrentVersionRun_249b {
  strings:
    $key_249b = { 77 f4 [2] 53 fa [2] 78 d6 [2] 56 f4 [2] 42 ef [2] 4d f5 [2] 53 e8 [2] 51 e9 [2] 4a ef [2] 56 e8 [2] 4a c7 }

  condition:
    any of them
}