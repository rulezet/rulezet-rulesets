rule TTP_XOR_QUAD_CurrentVersionRun_d1f2 {
  strings:
    $key_d1f2 = { 82 9d [2] a6 93 [2] 8d bf [2] a3 9d [2] b7 86 [2] b8 9c [2] a6 81 [2] a4 80 [2] bf 86 [2] a3 81 [2] bf ae }

  condition:
    any of them
}