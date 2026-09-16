rule TTP_XOR_QUAD_CurrentVersionRun_03cc {
  strings:
    $key_03cc = { 50 a3 [2] 74 ad [2] 5f 81 [2] 71 a3 [2] 65 b8 [2] 6a a2 [2] 74 bf [2] 76 be [2] 6d b8 [2] 71 bf [2] 6d 90 }

  condition:
    any of them
}