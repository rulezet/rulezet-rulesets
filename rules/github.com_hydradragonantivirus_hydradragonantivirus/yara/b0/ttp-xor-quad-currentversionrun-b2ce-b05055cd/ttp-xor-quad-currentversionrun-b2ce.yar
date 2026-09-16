rule TTP_XOR_QUAD_CurrentVersionRun_b2ce {
  strings:
    $key_b2ce = { e1 a1 [2] c5 af [2] ee 83 [2] c0 a1 [2] d4 ba [2] db a0 [2] c5 bd [2] c7 bc [2] dc ba [2] c0 bd [2] dc 92 }

  condition:
    any of them
}