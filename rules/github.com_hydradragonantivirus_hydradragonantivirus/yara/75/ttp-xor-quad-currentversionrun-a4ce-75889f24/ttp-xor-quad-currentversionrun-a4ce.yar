rule TTP_XOR_QUAD_CurrentVersionRun_a4ce {
  strings:
    $key_a4ce = { f7 a1 [2] d3 af [2] f8 83 [2] d6 a1 [2] c2 ba [2] cd a0 [2] d3 bd [2] d1 bc [2] ca ba [2] d6 bd [2] ca 92 }

  condition:
    any of them
}