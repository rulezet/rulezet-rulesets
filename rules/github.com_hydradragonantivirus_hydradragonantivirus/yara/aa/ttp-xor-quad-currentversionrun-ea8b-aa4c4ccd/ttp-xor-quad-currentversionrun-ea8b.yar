rule TTP_XOR_QUAD_CurrentVersionRun_ea8b {
  strings:
    $key_ea8b = { b9 e4 [2] 9d ea [2] b6 c6 [2] 98 e4 [2] 8c ff [2] 83 e5 [2] 9d f8 [2] 9f f9 [2] 84 ff [2] 98 f8 [2] 84 d7 }

  condition:
    any of them
}