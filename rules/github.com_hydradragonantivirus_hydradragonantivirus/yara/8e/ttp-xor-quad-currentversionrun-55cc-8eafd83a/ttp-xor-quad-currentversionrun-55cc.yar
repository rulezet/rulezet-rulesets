rule TTP_XOR_QUAD_CurrentVersionRun_55cc {
  strings:
    $key_55cc = { 06 a3 [2] 22 ad [2] 09 81 [2] 27 a3 [2] 33 b8 [2] 3c a2 [2] 22 bf [2] 20 be [2] 3b b8 [2] 27 bf [2] 3b 90 }

  condition:
    any of them
}