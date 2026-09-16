rule TTP_XOR_QUAD_CurrentVersionRun_3e77 {
  strings:
    $key_3e77 = { 6d 18 [2] 49 16 [2] 62 3a [2] 4c 18 [2] 58 03 [2] 57 19 [2] 49 04 [2] 4b 05 [2] 50 03 [2] 4c 04 [2] 50 2b }

  condition:
    any of them
}