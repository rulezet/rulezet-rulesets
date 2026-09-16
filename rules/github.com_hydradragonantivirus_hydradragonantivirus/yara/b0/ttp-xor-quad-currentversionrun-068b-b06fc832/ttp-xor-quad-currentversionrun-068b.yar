rule TTP_XOR_QUAD_CurrentVersionRun_068b {
  strings:
    $key_068b = { 55 e4 [2] 71 ea [2] 5a c6 [2] 74 e4 [2] 60 ff [2] 6f e5 [2] 71 f8 [2] 73 f9 [2] 68 ff [2] 74 f8 [2] 68 d7 }

  condition:
    any of them
}