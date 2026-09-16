rule TTP_XOR_QUAD_CurrentVersionRun_96cc {
  strings:
    $key_96cc = { c5 a3 [2] e1 ad [2] ca 81 [2] e4 a3 [2] f0 b8 [2] ff a2 [2] e1 bf [2] e3 be [2] f8 b8 [2] e4 bf [2] f8 90 }

  condition:
    any of them
}