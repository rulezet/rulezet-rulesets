rule TTP_XOR_QUAD_CurrentVersionRun_9580 {
  strings:
    $key_9580 = { c6 ef [2] e2 e1 [2] c9 cd [2] e7 ef [2] f3 f4 [2] fc ee [2] e2 f3 [2] e0 f2 [2] fb f4 [2] e7 f3 [2] fb dc }

  condition:
    any of them
}