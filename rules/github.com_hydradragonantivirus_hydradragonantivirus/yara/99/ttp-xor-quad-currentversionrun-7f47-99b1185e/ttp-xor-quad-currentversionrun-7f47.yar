rule TTP_XOR_QUAD_CurrentVersionRun_7f47 {
  strings:
    $key_7f47 = { 2c 28 [2] 08 26 [2] 23 0a [2] 0d 28 [2] 19 33 [2] 16 29 [2] 08 34 [2] 0a 35 [2] 11 33 [2] 0d 34 [2] 11 1b }

  condition:
    any of them
}