rule TTP_XOR_QUAD_CurrentVersionRun_e19b {
  strings:
    $key_e19b = { b2 f4 [2] 96 fa [2] bd d6 [2] 93 f4 [2] 87 ef [2] 88 f5 [2] 96 e8 [2] 94 e9 [2] 8f ef [2] 93 e8 [2] 8f c7 }

  condition:
    any of them
}