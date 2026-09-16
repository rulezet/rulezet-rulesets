rule TTP_XOR_QUAD_CurrentVersionRun_0f8c {
  strings:
    $key_0f8c = { 5c e3 [2] 78 ed [2] 53 c1 [2] 7d e3 [2] 69 f8 [2] 66 e2 [2] 78 ff [2] 7a fe [2] 61 f8 [2] 7d ff [2] 61 d0 }

  condition:
    any of them
}