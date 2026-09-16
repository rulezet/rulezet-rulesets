rule TTP_XOR_QUAD_CurrentVersionRun_e69b {
  strings:
    $key_e69b = { b5 f4 [2] 91 fa [2] ba d6 [2] 94 f4 [2] 80 ef [2] 8f f5 [2] 91 e8 [2] 93 e9 [2] 88 ef [2] 94 e8 [2] 88 c7 }

  condition:
    any of them
}