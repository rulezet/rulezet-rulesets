rule TTP_XOR_QUAD_CurrentVersionRun_41f2 {
  strings:
    $key_41f2 = { 12 9d [2] 36 93 [2] 1d bf [2] 33 9d [2] 27 86 [2] 28 9c [2] 36 81 [2] 34 80 [2] 2f 86 [2] 33 81 [2] 2f ae }

  condition:
    any of them
}