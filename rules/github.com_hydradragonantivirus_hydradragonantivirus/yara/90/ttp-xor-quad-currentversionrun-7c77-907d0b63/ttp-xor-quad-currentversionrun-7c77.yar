rule TTP_XOR_QUAD_CurrentVersionRun_7c77 {
  strings:
    $key_7c77 = { 2f 18 [2] 0b 16 [2] 20 3a [2] 0e 18 [2] 1a 03 [2] 15 19 [2] 0b 04 [2] 09 05 [2] 12 03 [2] 0e 04 [2] 12 2b }

  condition:
    any of them
}