rule TTP_XOR_QUAD_CurrentVersionRun_0b8c {
  strings:
    $key_0b8c = { 58 e3 [2] 7c ed [2] 57 c1 [2] 79 e3 [2] 6d f8 [2] 62 e2 [2] 7c ff [2] 7e fe [2] 65 f8 [2] 79 ff [2] 65 d0 }

  condition:
    any of them
}