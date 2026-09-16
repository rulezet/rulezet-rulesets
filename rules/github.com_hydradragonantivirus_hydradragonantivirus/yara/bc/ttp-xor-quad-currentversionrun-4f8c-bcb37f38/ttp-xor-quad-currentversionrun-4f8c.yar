rule TTP_XOR_QUAD_CurrentVersionRun_4f8c {
  strings:
    $key_4f8c = { 1c e3 [2] 38 ed [2] 13 c1 [2] 3d e3 [2] 29 f8 [2] 26 e2 [2] 38 ff [2] 3a fe [2] 21 f8 [2] 3d ff [2] 21 d0 }

  condition:
    any of them
}