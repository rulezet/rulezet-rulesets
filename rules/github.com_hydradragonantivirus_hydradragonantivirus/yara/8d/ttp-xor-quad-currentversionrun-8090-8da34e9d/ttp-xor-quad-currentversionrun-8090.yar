rule TTP_XOR_QUAD_CurrentVersionRun_8090 {
  strings:
    $key_8090 = { d3 ff [2] f7 f1 [2] dc dd [2] f2 ff [2] e6 e4 [2] e9 fe [2] f7 e3 [2] f5 e2 [2] ee e4 [2] f2 e3 [2] ee cc }

  condition:
    any of them
}