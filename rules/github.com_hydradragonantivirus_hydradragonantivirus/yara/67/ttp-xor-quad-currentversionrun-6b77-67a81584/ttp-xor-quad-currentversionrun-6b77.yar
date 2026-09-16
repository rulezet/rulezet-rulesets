rule TTP_XOR_QUAD_CurrentVersionRun_6b77 {
  strings:
    $key_6b77 = { 38 18 [2] 1c 16 [2] 37 3a [2] 19 18 [2] 0d 03 [2] 02 19 [2] 1c 04 [2] 1e 05 [2] 05 03 [2] 19 04 [2] 05 2b }

  condition:
    any of them
}