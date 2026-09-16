rule TTP_XOR_QUAD_CurrentVersionRun_53cc {
  strings:
    $key_53cc = { 00 a3 [2] 24 ad [2] 0f 81 [2] 21 a3 [2] 35 b8 [2] 3a a2 [2] 24 bf [2] 26 be [2] 3d b8 [2] 21 bf [2] 3d 90 }

  condition:
    any of them
}