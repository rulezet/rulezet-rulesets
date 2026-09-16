rule TTP_XOR_QUAD_CurrentVersionRun_c49b {
  strings:
    $key_c49b = { 97 f4 [2] b3 fa [2] 98 d6 [2] b6 f4 [2] a2 ef [2] ad f5 [2] b3 e8 [2] b1 e9 [2] aa ef [2] b6 e8 [2] aa c7 }

  condition:
    any of them
}