rule TTP_XOR_QUAD_CurrentVersionRun_449b {
  strings:
    $key_449b = { 17 f4 [2] 33 fa [2] 18 d6 [2] 36 f4 [2] 22 ef [2] 2d f5 [2] 33 e8 [2] 31 e9 [2] 2a ef [2] 36 e8 [2] 2a c7 }

  condition:
    any of them
}