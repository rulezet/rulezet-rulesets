rule TTP_XOR_QUAD_CurrentVersionRun_2047 {
  strings:
    $key_2047 = { 73 28 [2] 57 26 [2] 7c 0a [2] 52 28 [2] 46 33 [2] 49 29 [2] 57 34 [2] 55 35 [2] 4e 33 [2] 52 34 [2] 4e 1b }

  condition:
    any of them
}