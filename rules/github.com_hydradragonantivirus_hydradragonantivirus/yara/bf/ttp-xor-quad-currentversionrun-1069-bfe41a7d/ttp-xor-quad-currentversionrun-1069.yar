rule TTP_XOR_QUAD_CurrentVersionRun_1069 {
  strings:
    $key_1069 = { 43 06 [2] 67 08 [2] 4c 24 [2] 62 06 [2] 76 1d [2] 79 07 [2] 67 1a [2] 65 1b [2] 7e 1d [2] 62 1a [2] 7e 35 }

  condition:
    any of them
}