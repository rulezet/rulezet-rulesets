rule TTP_XOR_QUAD_CurrentVersionRun_2777 {
  strings:
    $key_2777 = { 74 18 [2] 50 16 [2] 7b 3a [2] 55 18 [2] 41 03 [2] 4e 19 [2] 50 04 [2] 52 05 [2] 49 03 [2] 55 04 [2] 49 2b }

  condition:
    any of them
}