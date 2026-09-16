rule TTP_XOR_QUAD_CurrentVersionRun_acdd {
  strings:
    $key_acdd = { ff b2 [2] db bc [2] f0 90 [2] de b2 [2] ca a9 [2] c5 b3 [2] db ae [2] d9 af [2] c2 a9 [2] de ae [2] c2 81 }

  condition:
    any of them
}