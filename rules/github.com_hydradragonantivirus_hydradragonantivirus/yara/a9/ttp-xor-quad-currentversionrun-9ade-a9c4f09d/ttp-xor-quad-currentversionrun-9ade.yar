rule TTP_XOR_QUAD_CurrentVersionRun_9ade {
  strings:
    $key_9ade = { c9 b1 [2] ed bf [2] c6 93 [2] e8 b1 [2] fc aa [2] f3 b0 [2] ed ad [2] ef ac [2] f4 aa [2] e8 ad [2] f4 82 }

  condition:
    any of them
}