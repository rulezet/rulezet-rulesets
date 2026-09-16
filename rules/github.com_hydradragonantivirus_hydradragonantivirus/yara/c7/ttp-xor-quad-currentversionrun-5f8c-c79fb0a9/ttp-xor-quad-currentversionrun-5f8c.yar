rule TTP_XOR_QUAD_CurrentVersionRun_5f8c {
  strings:
    $key_5f8c = { 0c e3 [2] 28 ed [2] 03 c1 [2] 2d e3 [2] 39 f8 [2] 36 e2 [2] 28 ff [2] 2a fe [2] 31 f8 [2] 2d ff [2] 31 d0 }

  condition:
    any of them
}