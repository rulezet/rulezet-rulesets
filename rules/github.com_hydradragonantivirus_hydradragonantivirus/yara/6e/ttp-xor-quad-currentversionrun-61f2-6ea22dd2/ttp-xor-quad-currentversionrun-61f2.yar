rule TTP_XOR_QUAD_CurrentVersionRun_61f2 {
  strings:
    $key_61f2 = { 32 9d [2] 16 93 [2] 3d bf [2] 13 9d [2] 07 86 [2] 08 9c [2] 16 81 [2] 14 80 [2] 0f 86 [2] 13 81 [2] 0f ae }

  condition:
    any of them
}