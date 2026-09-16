rule TTP_XOR_QUAD_CurrentVersionRun_7547 {
  strings:
    $key_7547 = { 26 28 [2] 02 26 [2] 29 0a [2] 07 28 [2] 13 33 [2] 1c 29 [2] 02 34 [2] 00 35 [2] 1b 33 [2] 07 34 [2] 1b 1b }

  condition:
    any of them
}