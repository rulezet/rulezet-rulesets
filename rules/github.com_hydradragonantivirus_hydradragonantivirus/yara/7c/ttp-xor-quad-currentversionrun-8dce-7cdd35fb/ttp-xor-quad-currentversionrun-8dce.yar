rule TTP_XOR_QUAD_CurrentVersionRun_8dce {
  strings:
    $key_8dce = { de a1 [2] fa af [2] d1 83 [2] ff a1 [2] eb ba [2] e4 a0 [2] fa bd [2] f8 bc [2] e3 ba [2] ff bd [2] e3 92 }

  condition:
    any of them
}