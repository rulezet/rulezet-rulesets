rule TTP_XOR_QUAD_CurrentVersionRun_51f2 {
  strings:
    $key_51f2 = { 02 9d [2] 26 93 [2] 0d bf [2] 23 9d [2] 37 86 [2] 38 9c [2] 26 81 [2] 24 80 [2] 3f 86 [2] 23 81 [2] 3f ae }

  condition:
    any of them
}