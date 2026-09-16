rule TTP_XOR_QUAD_CurrentVersionRun_74cc {
  strings:
    $key_74cc = { 27 a3 [2] 03 ad [2] 28 81 [2] 06 a3 [2] 12 b8 [2] 1d a2 [2] 03 bf [2] 01 be [2] 1a b8 [2] 06 bf [2] 1a 90 }

  condition:
    any of them
}