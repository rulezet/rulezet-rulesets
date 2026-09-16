rule TTP_XOR_QUAD_CurrentVersionRun_8298 {
  strings:
    $key_8298 = { d1 f7 [2] f5 f9 [2] de d5 [2] f0 f7 [2] e4 ec [2] eb f6 [2] f5 eb [2] f7 ea [2] ec ec [2] f0 eb [2] ec c4 }

  condition:
    any of them
}