rule TTP_XOR_QUAD_CurrentVersionRun_e89b {
  strings:
    $key_e89b = { bb f4 [2] 9f fa [2] b4 d6 [2] 9a f4 [2] 8e ef [2] 81 f5 [2] 9f e8 [2] 9d e9 [2] 86 ef [2] 9a e8 [2] 86 c7 }

  condition:
    any of them
}