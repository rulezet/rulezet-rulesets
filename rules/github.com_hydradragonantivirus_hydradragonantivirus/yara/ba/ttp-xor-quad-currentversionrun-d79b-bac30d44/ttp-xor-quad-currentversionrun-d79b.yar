rule TTP_XOR_QUAD_CurrentVersionRun_d79b {
  strings:
    $key_d79b = { 84 f4 [2] a0 fa [2] 8b d6 [2] a5 f4 [2] b1 ef [2] be f5 [2] a0 e8 [2] a2 e9 [2] b9 ef [2] a5 e8 [2] b9 c7 }

  condition:
    any of them
}