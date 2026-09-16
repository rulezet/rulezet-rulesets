rule TTP_XOR_QUAD_CurrentVersionRun_4b8c {
  strings:
    $key_4b8c = { 18 e3 [2] 3c ed [2] 17 c1 [2] 39 e3 [2] 2d f8 [2] 22 e2 [2] 3c ff [2] 3e fe [2] 25 f8 [2] 39 ff [2] 25 d0 }

  condition:
    any of them
}