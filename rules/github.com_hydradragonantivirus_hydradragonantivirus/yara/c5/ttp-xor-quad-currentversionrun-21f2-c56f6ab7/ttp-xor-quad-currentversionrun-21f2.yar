rule TTP_XOR_QUAD_CurrentVersionRun_21f2 {
  strings:
    $key_21f2 = { 72 9d [2] 56 93 [2] 7d bf [2] 53 9d [2] 47 86 [2] 48 9c [2] 56 81 [2] 54 80 [2] 4f 86 [2] 53 81 [2] 4f ae }

  condition:
    any of them
}