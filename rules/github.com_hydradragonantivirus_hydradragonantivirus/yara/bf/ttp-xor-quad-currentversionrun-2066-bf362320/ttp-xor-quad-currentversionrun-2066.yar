rule TTP_XOR_QUAD_CurrentVersionRun_2066 {
  strings:
    $key_2066 = { 73 09 [2] 57 07 [2] 7c 2b [2] 52 09 [2] 46 12 [2] 49 08 [2] 57 15 [2] 55 14 [2] 4e 12 [2] 52 15 [2] 4e 3a }

  condition:
    any of them
}