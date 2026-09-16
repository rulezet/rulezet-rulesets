rule TTP_XOR_QUAD_CurrentVersionRun_34cc {
  strings:
    $key_34cc = { 67 a3 [2] 43 ad [2] 68 81 [2] 46 a3 [2] 52 b8 [2] 5d a2 [2] 43 bf [2] 41 be [2] 5a b8 [2] 46 bf [2] 5a 90 }

  condition:
    any of them
}