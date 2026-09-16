rule TTP_XOR_QUAD_CurrentVersionRun_1e77 {
  strings:
    $key_1e77 = { 4d 18 [2] 69 16 [2] 42 3a [2] 6c 18 [2] 78 03 [2] 77 19 [2] 69 04 [2] 6b 05 [2] 70 03 [2] 6c 04 [2] 70 2b }

  condition:
    any of them
}