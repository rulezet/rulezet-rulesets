rule TTP_XOR_QUAD_CurrentVersionRun_5a8c {
  strings:
    $key_5a8c = { 09 e3 [2] 2d ed [2] 06 c1 [2] 28 e3 [2] 3c f8 [2] 33 e2 [2] 2d ff [2] 2f fe [2] 34 f8 [2] 28 ff [2] 34 d0 }

  condition:
    any of them
}