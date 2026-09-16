rule TTP_XOR_QUAD_CurrentVersionRun_a3ce {
  strings:
    $key_a3ce = { f0 a1 [2] d4 af [2] ff 83 [2] d1 a1 [2] c5 ba [2] ca a0 [2] d4 bd [2] d6 bc [2] cd ba [2] d1 bd [2] cd 92 }

  condition:
    any of them
}