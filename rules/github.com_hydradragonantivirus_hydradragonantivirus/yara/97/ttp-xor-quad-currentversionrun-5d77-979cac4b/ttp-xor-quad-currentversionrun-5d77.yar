rule TTP_XOR_QUAD_CurrentVersionRun_5d77 {
  strings:
    $key_5d77 = { 0e 18 [2] 2a 16 [2] 01 3a [2] 2f 18 [2] 3b 03 [2] 34 19 [2] 2a 04 [2] 28 05 [2] 33 03 [2] 2f 04 [2] 33 2b }

  condition:
    any of them
}