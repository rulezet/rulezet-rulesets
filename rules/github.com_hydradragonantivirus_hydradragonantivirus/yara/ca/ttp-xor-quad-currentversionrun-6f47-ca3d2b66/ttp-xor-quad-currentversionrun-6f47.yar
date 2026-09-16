rule TTP_XOR_QUAD_CurrentVersionRun_6f47 {
  strings:
    $key_6f47 = { 3c 28 [2] 18 26 [2] 33 0a [2] 1d 28 [2] 09 33 [2] 06 29 [2] 18 34 [2] 1a 35 [2] 01 33 [2] 1d 34 [2] 01 1b }

  condition:
    any of them
}