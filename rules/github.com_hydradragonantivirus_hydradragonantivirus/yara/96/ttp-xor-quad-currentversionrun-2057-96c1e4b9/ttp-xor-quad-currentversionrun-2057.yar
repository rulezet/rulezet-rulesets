rule TTP_XOR_QUAD_CurrentVersionRun_2057 {
  strings:
    $key_2057 = { 73 38 [2] 57 36 [2] 7c 1a [2] 52 38 [2] 46 23 [2] 49 39 [2] 57 24 [2] 55 25 [2] 4e 23 [2] 52 24 [2] 4e 0b }

  condition:
    any of them
}