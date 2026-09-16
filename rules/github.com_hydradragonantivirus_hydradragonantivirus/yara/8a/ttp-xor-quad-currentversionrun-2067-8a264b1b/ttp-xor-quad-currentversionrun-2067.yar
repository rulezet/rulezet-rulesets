rule TTP_XOR_QUAD_CurrentVersionRun_2067 {
  strings:
    $key_2067 = { 73 08 [2] 57 06 [2] 7c 2a [2] 52 08 [2] 46 13 [2] 49 09 [2] 57 14 [2] 55 15 [2] 4e 13 [2] 52 14 [2] 4e 3b }

  condition:
    any of them
}