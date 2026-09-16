rule TTP_XOR_QUAD_CurrentVersionRun_31f2 {
  strings:
    $key_31f2 = { 62 9d [2] 46 93 [2] 6d bf [2] 43 9d [2] 57 86 [2] 58 9c [2] 46 81 [2] 44 80 [2] 5f 86 [2] 43 81 [2] 5f ae }

  condition:
    any of them
}