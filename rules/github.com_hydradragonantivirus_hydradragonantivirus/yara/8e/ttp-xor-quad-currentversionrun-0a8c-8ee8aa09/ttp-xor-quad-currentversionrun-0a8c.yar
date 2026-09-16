rule TTP_XOR_QUAD_CurrentVersionRun_0a8c {
  strings:
    $key_0a8c = { 59 e3 [2] 7d ed [2] 56 c1 [2] 78 e3 [2] 6c f8 [2] 63 e2 [2] 7d ff [2] 7f fe [2] 64 f8 [2] 78 ff [2] 64 d0 }

  condition:
    any of them
}