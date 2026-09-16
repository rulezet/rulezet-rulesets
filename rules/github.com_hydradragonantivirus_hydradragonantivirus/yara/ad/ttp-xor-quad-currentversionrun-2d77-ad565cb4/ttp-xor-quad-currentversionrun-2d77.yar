rule TTP_XOR_QUAD_CurrentVersionRun_2d77 {
  strings:
    $key_2d77 = { 7e 18 [2] 5a 16 [2] 71 3a [2] 5f 18 [2] 4b 03 [2] 44 19 [2] 5a 04 [2] 58 05 [2] 43 03 [2] 5f 04 [2] 43 2b }

  condition:
    any of them
}