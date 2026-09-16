rule TTP_XOR_QUAD_CurrentVersionRun_5e8c {
  strings:
    $key_5e8c = { 0d e3 [2] 29 ed [2] 02 c1 [2] 2c e3 [2] 38 f8 [2] 37 e2 [2] 29 ff [2] 2b fe [2] 30 f8 [2] 2c ff [2] 30 d0 }

  condition:
    any of them
}