rule TTP_XOR_QUAD_CurrentVersionRun_c89b {
  strings:
    $key_c89b = { 9b f4 [2] bf fa [2] 94 d6 [2] ba f4 [2] ae ef [2] a1 f5 [2] bf e8 [2] bd e9 [2] a6 ef [2] ba e8 [2] a6 c7 }

  condition:
    any of them
}