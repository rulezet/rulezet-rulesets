rule TTP_XOR_QUAD_CurrentVersionRun_309b {
  strings:
    $key_309b = { 63 f4 [2] 47 fa [2] 6c d6 [2] 42 f4 [2] 56 ef [2] 59 f5 [2] 47 e8 [2] 45 e9 [2] 5e ef [2] 42 e8 [2] 5e c7 }

  condition:
    any of them
}