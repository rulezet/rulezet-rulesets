rule TTP_XOR_QUAD_CurrentVersionRun_398b {
  strings:
    $key_398b = { 6a e4 [2] 4e ea [2] 65 c6 [2] 4b e4 [2] 5f ff [2] 50 e5 [2] 4e f8 [2] 4c f9 [2] 57 ff [2] 4b f8 [2] 57 d7 }

  condition:
    any of them
}