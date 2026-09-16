rule TTP_XOR_QUAD_CurrentVersionRun_149b {
  strings:
    $key_149b = { 47 f4 [2] 63 fa [2] 48 d6 [2] 66 f4 [2] 72 ef [2] 7d f5 [2] 63 e8 [2] 61 e9 [2] 7a ef [2] 66 e8 [2] 7a c7 }

  condition:
    any of them
}