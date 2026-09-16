rule TTP_XOR_QUAD_CurrentVersionRun_67cc {
  strings:
    $key_67cc = { 34 a3 [2] 10 ad [2] 3b 81 [2] 15 a3 [2] 01 b8 [2] 0e a2 [2] 10 bf [2] 12 be [2] 09 b8 [2] 15 bf [2] 09 90 }

  condition:
    any of them
}