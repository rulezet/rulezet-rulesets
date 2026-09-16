rule TTP_XOR_QUAD_CurrentVersionRun_46cc {
  strings:
    $key_46cc = { 15 a3 [2] 31 ad [2] 1a 81 [2] 34 a3 [2] 20 b8 [2] 2f a2 [2] 31 bf [2] 33 be [2] 28 b8 [2] 34 bf [2] 28 90 }

  condition:
    any of them
}