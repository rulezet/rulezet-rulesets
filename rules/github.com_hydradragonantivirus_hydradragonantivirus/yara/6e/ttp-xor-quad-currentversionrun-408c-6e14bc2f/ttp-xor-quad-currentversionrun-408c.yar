rule TTP_XOR_QUAD_CurrentVersionRun_408c {
  strings:
    $key_408c = { 13 e3 [2] 37 ed [2] 1c c1 [2] 32 e3 [2] 26 f8 [2] 29 e2 [2] 37 ff [2] 35 fe [2] 2e f8 [2] 32 ff [2] 2e d0 }

  condition:
    any of them
}