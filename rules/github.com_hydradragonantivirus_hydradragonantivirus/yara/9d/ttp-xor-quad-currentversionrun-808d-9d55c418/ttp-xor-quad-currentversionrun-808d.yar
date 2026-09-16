rule TTP_XOR_QUAD_CurrentVersionRun_808d {
  strings:
    $key_808d = { d3 e2 [2] f7 ec [2] dc c0 [2] f2 e2 [2] e6 f9 [2] e9 e3 [2] f7 fe [2] f5 ff [2] ee f9 [2] f2 fe [2] ee d1 }

  condition:
    any of them
}