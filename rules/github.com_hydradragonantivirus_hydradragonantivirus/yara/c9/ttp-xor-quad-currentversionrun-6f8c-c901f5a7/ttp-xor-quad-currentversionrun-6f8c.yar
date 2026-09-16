rule TTP_XOR_QUAD_CurrentVersionRun_6f8c {
  strings:
    $key_6f8c = { 3c e3 [2] 18 ed [2] 33 c1 [2] 1d e3 [2] 09 f8 [2] 06 e2 [2] 18 ff [2] 1a fe [2] 01 f8 [2] 1d ff [2] 01 d0 }

  condition:
    any of them
}