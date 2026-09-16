rule TTP_XOR_QUAD_CurrentVersionRun_158b {
  strings:
    $key_158b = { 46 e4 [2] 62 ea [2] 49 c6 [2] 67 e4 [2] 73 ff [2] 7c e5 [2] 62 f8 [2] 60 f9 [2] 7b ff [2] 67 f8 [2] 7b d7 }

  condition:
    any of them
}