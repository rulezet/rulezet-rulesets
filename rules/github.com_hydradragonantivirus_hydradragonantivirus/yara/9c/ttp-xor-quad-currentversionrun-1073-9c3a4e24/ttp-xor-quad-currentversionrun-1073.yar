rule TTP_XOR_QUAD_CurrentVersionRun_1073 {
  strings:
    $key_1073 = { 43 1c [2] 67 12 [2] 4c 3e [2] 62 1c [2] 76 07 [2] 79 1d [2] 67 00 [2] 65 01 [2] 7e 07 [2] 62 00 [2] 7e 2f }

  condition:
    any of them
}