rule TTP_XOR_QUAD_CurrentVersionRun_01f2 {
  strings:
    $key_01f2 = { 52 9d [2] 76 93 [2] 5d bf [2] 73 9d [2] 67 86 [2] 68 9c [2] 76 81 [2] 74 80 [2] 6f 86 [2] 73 81 [2] 6f ae }

  condition:
    any of them
}