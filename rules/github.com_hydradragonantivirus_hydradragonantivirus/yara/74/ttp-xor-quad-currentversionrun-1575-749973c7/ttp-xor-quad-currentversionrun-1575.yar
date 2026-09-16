rule TTP_XOR_QUAD_CurrentVersionRun_1575 {
  strings:
    $key_1575 = { 46 1a [2] 62 14 [2] 49 38 [2] 67 1a [2] 73 01 [2] 7c 1b [2] 62 06 [2] 60 07 [2] 7b 01 [2] 67 06 [2] 7b 29 }

  condition:
    any of them
}