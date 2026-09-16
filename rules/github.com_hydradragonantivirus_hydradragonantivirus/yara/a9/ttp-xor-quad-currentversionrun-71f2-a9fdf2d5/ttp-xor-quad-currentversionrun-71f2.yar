rule TTP_XOR_QUAD_CurrentVersionRun_71f2 {
  strings:
    $key_71f2 = { 22 9d [2] 06 93 [2] 2d bf [2] 03 9d [2] 17 86 [2] 18 9c [2] 06 81 [2] 04 80 [2] 1f 86 [2] 03 81 [2] 1f ae }

  condition:
    any of them
}