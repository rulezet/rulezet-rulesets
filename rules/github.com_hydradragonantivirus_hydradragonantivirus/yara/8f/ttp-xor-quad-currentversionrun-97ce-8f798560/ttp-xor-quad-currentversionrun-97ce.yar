rule TTP_XOR_QUAD_CurrentVersionRun_97ce {
  strings:
    $key_97ce = { c4 a1 [2] e0 af [2] cb 83 [2] e5 a1 [2] f1 ba [2] fe a0 [2] e0 bd [2] e2 bc [2] f9 ba [2] e5 bd [2] f9 92 }

  condition:
    any of them
}