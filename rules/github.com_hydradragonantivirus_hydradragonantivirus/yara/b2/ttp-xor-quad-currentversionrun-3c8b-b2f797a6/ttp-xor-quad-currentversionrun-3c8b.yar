rule TTP_XOR_QUAD_CurrentVersionRun_3c8b {
  strings:
    $key_3c8b = { 6f e4 [2] 4b ea [2] 60 c6 [2] 4e e4 [2] 5a ff [2] 55 e5 [2] 4b f8 [2] 49 f9 [2] 52 ff [2] 4e f8 [2] 52 d7 }

  condition:
    any of them
}