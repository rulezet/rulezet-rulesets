rule TTP_XOR_QUAD_CurrentVersionRun_0f77 {
  strings:
    $key_0f77 = { 5c 18 [2] 78 16 [2] 53 3a [2] 7d 18 [2] 69 03 [2] 66 19 [2] 78 04 [2] 7a 05 [2] 61 03 [2] 7d 04 [2] 61 2b }

  condition:
    any of them
}