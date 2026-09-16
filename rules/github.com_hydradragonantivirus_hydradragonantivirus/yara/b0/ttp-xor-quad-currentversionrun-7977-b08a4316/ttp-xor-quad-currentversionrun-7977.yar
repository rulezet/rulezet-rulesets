rule TTP_XOR_QUAD_CurrentVersionRun_7977 {
  strings:
    $key_7977 = { 2a 18 [2] 0e 16 [2] 25 3a [2] 0b 18 [2] 1f 03 [2] 10 19 [2] 0e 04 [2] 0c 05 [2] 17 03 [2] 0b 04 [2] 17 2b }

  condition:
    any of them
}