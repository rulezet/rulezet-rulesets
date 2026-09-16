rule TTP_XOR_QUAD_CurrentVersionRun_47cc {
  strings:
    $key_47cc = { 14 a3 [2] 30 ad [2] 1b 81 [2] 35 a3 [2] 21 b8 [2] 2e a2 [2] 30 bf [2] 32 be [2] 29 b8 [2] 35 bf [2] 29 90 }

  condition:
    any of them
}