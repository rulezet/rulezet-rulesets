rule TTP_XOR_QUAD_CurrentVersionRun_ef8b {
  strings:
    $key_ef8b = { bc e4 [2] 98 ea [2] b3 c6 [2] 9d e4 [2] 89 ff [2] 86 e5 [2] 98 f8 [2] 9a f9 [2] 81 ff [2] 9d f8 [2] 81 d7 }

  condition:
    any of them
}