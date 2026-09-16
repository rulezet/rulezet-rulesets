rule TTP_XOR_QUAD_CurrentVersionRun_3b77 {
  strings:
    $key_3b77 = { 68 18 [2] 4c 16 [2] 67 3a [2] 49 18 [2] 5d 03 [2] 52 19 [2] 4c 04 [2] 4e 05 [2] 55 03 [2] 49 04 [2] 55 2b }

  condition:
    any of them
}