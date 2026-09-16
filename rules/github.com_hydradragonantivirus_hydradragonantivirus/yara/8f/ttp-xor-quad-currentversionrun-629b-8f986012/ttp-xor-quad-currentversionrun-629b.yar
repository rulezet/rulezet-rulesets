rule TTP_XOR_QUAD_CurrentVersionRun_629b {
  strings:
    $key_629b = { 31 f4 [2] 15 fa [2] 3e d6 [2] 10 f4 [2] 04 ef [2] 0b f5 [2] 15 e8 [2] 17 e9 [2] 0c ef [2] 10 e8 [2] 0c c7 }

  condition:
    any of them
}