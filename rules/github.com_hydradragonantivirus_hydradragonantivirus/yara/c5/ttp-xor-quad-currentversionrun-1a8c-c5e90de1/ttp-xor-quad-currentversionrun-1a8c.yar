rule TTP_XOR_QUAD_CurrentVersionRun_1a8c {
  strings:
    $key_1a8c = { 49 e3 [2] 6d ed [2] 46 c1 [2] 68 e3 [2] 7c f8 [2] 73 e2 [2] 6d ff [2] 6f fe [2] 74 f8 [2] 68 ff [2] 74 d0 }

  condition:
    any of them
}