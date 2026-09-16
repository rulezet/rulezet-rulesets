rule TTP_XOR_QUAD_CurrentVersionRun_3e8c {
  strings:
    $key_3e8c = { 6d e3 [2] 49 ed [2] 62 c1 [2] 4c e3 [2] 58 f8 [2] 57 e2 [2] 49 ff [2] 4b fe [2] 50 f8 [2] 4c ff [2] 50 d0 }

  condition:
    any of them
}