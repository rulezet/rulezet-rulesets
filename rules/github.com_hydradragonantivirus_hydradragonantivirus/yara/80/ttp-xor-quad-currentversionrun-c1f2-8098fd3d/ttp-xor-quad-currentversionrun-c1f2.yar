rule TTP_XOR_QUAD_CurrentVersionRun_c1f2 {
  strings:
    $key_c1f2 = { 92 9d [2] b6 93 [2] 9d bf [2] b3 9d [2] a7 86 [2] a8 9c [2] b6 81 [2] b4 80 [2] af 86 [2] b3 81 [2] af ae }

  condition:
    any of them
}