rule TTP_XOR_QUAD_CurrentVersionRun_91cc {
  strings:
    $key_91cc = { c2 a3 [2] e6 ad [2] cd 81 [2] e3 a3 [2] f7 b8 [2] f8 a2 [2] e6 bf [2] e4 be [2] ff b8 [2] e3 bf [2] ff 90 }

  condition:
    any of them
}