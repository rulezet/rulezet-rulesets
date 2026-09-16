rule TTP_XOR_QUAD_CurrentVersionRun_c79b {
  strings:
    $key_c79b = { 94 f4 [2] b0 fa [2] 9b d6 [2] b5 f4 [2] a1 ef [2] ae f5 [2] b0 e8 [2] b2 e9 [2] a9 ef [2] b5 e8 [2] a9 c7 }

  condition:
    any of them
}