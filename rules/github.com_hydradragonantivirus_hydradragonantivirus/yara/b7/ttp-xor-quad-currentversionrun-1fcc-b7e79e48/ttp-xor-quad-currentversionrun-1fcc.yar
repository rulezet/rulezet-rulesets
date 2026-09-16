rule TTP_XOR_QUAD_CurrentVersionRun_1fcc {
  strings:
    $key_1fcc = { 4c a3 [2] 68 ad [2] 43 81 [2] 6d a3 [2] 79 b8 [2] 76 a2 [2] 68 bf [2] 6a be [2] 71 b8 [2] 6d bf [2] 71 90 }

  condition:
    any of them
}