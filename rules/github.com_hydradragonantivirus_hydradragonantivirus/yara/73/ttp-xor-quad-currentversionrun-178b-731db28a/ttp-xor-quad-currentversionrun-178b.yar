rule TTP_XOR_QUAD_CurrentVersionRun_178b {
  strings:
    $key_178b = { 44 e4 [2] 60 ea [2] 4b c6 [2] 65 e4 [2] 71 ff [2] 7e e5 [2] 60 f8 [2] 62 f9 [2] 79 ff [2] 65 f8 [2] 79 d7 }

  condition:
    any of them
}