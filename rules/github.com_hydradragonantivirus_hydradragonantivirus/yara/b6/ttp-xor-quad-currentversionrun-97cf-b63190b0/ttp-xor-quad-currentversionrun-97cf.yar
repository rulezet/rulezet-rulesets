rule TTP_XOR_QUAD_CurrentVersionRun_97cf {
  strings:
    $key_97cf = { c4 a0 [2] e0 ae [2] cb 82 [2] e5 a0 [2] f1 bb [2] fe a1 [2] e0 bc [2] e2 bd [2] f9 bb [2] e5 bc [2] f9 93 }

  condition:
    any of them
}