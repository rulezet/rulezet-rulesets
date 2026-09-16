rule TTP_XOR_QUAD_CurrentVersionRun_7e8c {
  strings:
    $key_7e8c = { 2d e3 [2] 09 ed [2] 22 c1 [2] 0c e3 [2] 18 f8 [2] 17 e2 [2] 09 ff [2] 0b fe [2] 10 f8 [2] 0c ff [2] 10 d0 }

  condition:
    any of them
}