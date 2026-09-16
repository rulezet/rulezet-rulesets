rule TTP_XOR_QUAD_CurrentVersionRun_f68b {
  strings:
    $key_f68b = { a5 e4 [2] 81 ea [2] aa c6 [2] 84 e4 [2] 90 ff [2] 9f e5 [2] 81 f8 [2] 83 f9 [2] 98 ff [2] 84 f8 [2] 98 d7 }

  condition:
    any of them
}