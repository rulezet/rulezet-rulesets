rule TTP_XOR_QUAD_CurrentVersionRun_a09b {
  strings:
    $key_a09b = { f3 f4 [2] d7 fa [2] fc d6 [2] d2 f4 [2] c6 ef [2] c9 f5 [2] d7 e8 [2] d5 e9 [2] ce ef [2] d2 e8 [2] ce c7 }

  condition:
    any of them
}