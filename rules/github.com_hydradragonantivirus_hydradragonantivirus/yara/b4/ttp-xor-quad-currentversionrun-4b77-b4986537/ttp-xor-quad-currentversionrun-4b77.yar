rule TTP_XOR_QUAD_CurrentVersionRun_4b77 {
  strings:
    $key_4b77 = { 18 18 [2] 3c 16 [2] 17 3a [2] 39 18 [2] 2d 03 [2] 22 19 [2] 3c 04 [2] 3e 05 [2] 25 03 [2] 39 04 [2] 25 2b }

  condition:
    any of them
}