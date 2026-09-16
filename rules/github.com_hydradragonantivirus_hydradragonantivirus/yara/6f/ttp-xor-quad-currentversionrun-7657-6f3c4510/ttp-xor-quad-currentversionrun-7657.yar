rule TTP_XOR_QUAD_CurrentVersionRun_7657 {
  strings:
    $key_7657 = { 25 38 [2] 01 36 [2] 2a 1a [2] 04 38 [2] 10 23 [2] 1f 39 [2] 01 24 [2] 03 25 [2] 18 23 [2] 04 24 [2] 18 0b }

  condition:
    any of them
}