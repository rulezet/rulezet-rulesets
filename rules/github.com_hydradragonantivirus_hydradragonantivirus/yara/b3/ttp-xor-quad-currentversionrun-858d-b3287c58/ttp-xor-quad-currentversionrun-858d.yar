rule TTP_XOR_QUAD_CurrentVersionRun_858d {
  strings:
    $key_858d = { d6 e2 [2] f2 ec [2] d9 c0 [2] f7 e2 [2] e3 f9 [2] ec e3 [2] f2 fe [2] f0 ff [2] eb f9 [2] f7 fe [2] eb d1 }

  condition:
    any of them
}