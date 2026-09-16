rule TTP_XOR_QUAD_CurrentVersionRun_7377 {
  strings:
    $key_7377 = { 20 18 [2] 04 16 [2] 2f 3a [2] 01 18 [2] 15 03 [2] 1a 19 [2] 04 04 [2] 06 05 [2] 1d 03 [2] 01 04 [2] 1d 2b }

  condition:
    any of them
}