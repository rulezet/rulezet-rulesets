rule TTP_XOR_QUAD_CurrentVersionRun_498b {
  strings:
    $key_498b = { 1a e4 [2] 3e ea [2] 15 c6 [2] 3b e4 [2] 2f ff [2] 20 e5 [2] 3e f8 [2] 3c f9 [2] 27 ff [2] 3b f8 [2] 27 d7 }

  condition:
    any of them
}