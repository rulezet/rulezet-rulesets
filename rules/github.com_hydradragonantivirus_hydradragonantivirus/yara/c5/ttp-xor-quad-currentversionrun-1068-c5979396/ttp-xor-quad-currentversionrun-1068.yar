rule TTP_XOR_QUAD_CurrentVersionRun_1068 {
  strings:
    $key_1068 = { 43 07 [2] 67 09 [2] 4c 25 [2] 62 07 [2] 76 1c [2] 79 06 [2] 67 1b [2] 65 1a [2] 7e 1c [2] 62 1b [2] 7e 34 }

  condition:
    any of them
}