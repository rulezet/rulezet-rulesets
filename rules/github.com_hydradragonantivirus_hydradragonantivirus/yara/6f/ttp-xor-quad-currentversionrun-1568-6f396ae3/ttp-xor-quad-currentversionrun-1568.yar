rule TTP_XOR_QUAD_CurrentVersionRun_1568 {
  strings:
    $key_1568 = { 46 07 [2] 62 09 [2] 49 25 [2] 67 07 [2] 73 1c [2] 7c 06 [2] 62 1b [2] 60 1a [2] 7b 1c [2] 67 1b [2] 7b 34 }

  condition:
    any of them
}