rule TTP_XOR_QUAD_CurrentVersionRun_63cc {
  strings:
    $key_63cc = { 30 a3 [2] 14 ad [2] 3f 81 [2] 11 a3 [2] 05 b8 [2] 0a a2 [2] 14 bf [2] 16 be [2] 0d b8 [2] 11 bf [2] 0d 90 }

  condition:
    any of them
}