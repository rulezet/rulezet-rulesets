rule TTP_XOR_QUAD_CurrentVersionRun_accf {
  strings:
    $key_accf = { ff a0 [2] db ae [2] f0 82 [2] de a0 [2] ca bb [2] c5 a1 [2] db bc [2] d9 bd [2] c2 bb [2] de bc [2] c2 93 }

  condition:
    any of them
}