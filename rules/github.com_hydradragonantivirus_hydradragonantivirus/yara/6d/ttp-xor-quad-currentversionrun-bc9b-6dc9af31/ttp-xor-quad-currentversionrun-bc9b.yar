rule TTP_XOR_QUAD_CurrentVersionRun_bc9b {
  strings:
    $key_bc9b = { ef f4 [2] cb fa [2] e0 d6 [2] ce f4 [2] da ef [2] d5 f5 [2] cb e8 [2] c9 e9 [2] d2 ef [2] ce e8 [2] d2 c7 }

  condition:
    any of them
}