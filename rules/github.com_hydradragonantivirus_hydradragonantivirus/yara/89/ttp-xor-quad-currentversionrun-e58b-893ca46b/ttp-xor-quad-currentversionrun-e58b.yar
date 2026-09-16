rule TTP_XOR_QUAD_CurrentVersionRun_e58b {
  strings:
    $key_e58b = { b6 e4 [2] 92 ea [2] b9 c6 [2] 97 e4 [2] 83 ff [2] 8c e5 [2] 92 f8 [2] 90 f9 [2] 8b ff [2] 97 f8 [2] 8b d7 }

  condition:
    any of them
}