rule TTP_XOR_QUAD_CurrentVersionRun_4e77 {
  strings:
    $key_4e77 = { 1d 18 [2] 39 16 [2] 12 3a [2] 3c 18 [2] 28 03 [2] 27 19 [2] 39 04 [2] 3b 05 [2] 20 03 [2] 3c 04 [2] 20 2b }

  condition:
    any of them
}