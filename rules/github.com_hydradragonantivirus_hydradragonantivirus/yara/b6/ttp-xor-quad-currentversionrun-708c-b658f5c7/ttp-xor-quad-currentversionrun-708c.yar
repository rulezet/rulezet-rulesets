rule TTP_XOR_QUAD_CurrentVersionRun_708c {
  strings:
    $key_708c = { 23 e3 [2] 07 ed [2] 2c c1 [2] 02 e3 [2] 16 f8 [2] 19 e2 [2] 07 ff [2] 05 fe [2] 1e f8 [2] 02 ff [2] 1e d0 }

  condition:
    any of them
}