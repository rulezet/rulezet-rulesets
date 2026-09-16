rule TTP_XOR_QUAD_CurrentVersionRun_23cc {
  strings:
    $key_23cc = { 70 a3 [2] 54 ad [2] 7f 81 [2] 51 a3 [2] 45 b8 [2] 4a a2 [2] 54 bf [2] 56 be [2] 4d b8 [2] 51 bf [2] 4d 90 }

  condition:
    any of them
}