rule TTP_XOR_QUAD_CurrentVersionRun_2fcc {
  strings:
    $key_2fcc = { 7c a3 [2] 58 ad [2] 73 81 [2] 5d a3 [2] 49 b8 [2] 46 a2 [2] 58 bf [2] 5a be [2] 41 b8 [2] 5d bf [2] 41 90 }

  condition:
    any of them
}