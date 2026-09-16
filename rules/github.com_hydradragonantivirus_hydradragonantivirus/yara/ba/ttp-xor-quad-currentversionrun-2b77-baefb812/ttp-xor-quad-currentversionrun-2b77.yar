rule TTP_XOR_QUAD_CurrentVersionRun_2b77 {
  strings:
    $key_2b77 = { 78 18 [2] 5c 16 [2] 77 3a [2] 59 18 [2] 4d 03 [2] 42 19 [2] 5c 04 [2] 5e 05 [2] 45 03 [2] 59 04 [2] 45 2b }

  condition:
    any of them
}