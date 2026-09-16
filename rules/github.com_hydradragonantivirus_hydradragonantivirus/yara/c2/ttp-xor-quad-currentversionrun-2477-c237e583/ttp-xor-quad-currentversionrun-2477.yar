rule TTP_XOR_QUAD_CurrentVersionRun_2477 {
  strings:
    $key_2477 = { 77 18 [2] 53 16 [2] 78 3a [2] 56 18 [2] 42 03 [2] 4d 19 [2] 53 04 [2] 51 05 [2] 4a 03 [2] 56 04 [2] 4a 2b }

  condition:
    any of them
}