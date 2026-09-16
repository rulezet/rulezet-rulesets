rule TTP_XOR_QUAD_CurrentVersionRun_6f67 {
  strings:
    $key_6f67 = { 3c 08 [2] 18 06 [2] 33 2a [2] 1d 08 [2] 09 13 [2] 06 09 [2] 18 14 [2] 1a 15 [2] 01 13 [2] 1d 14 [2] 01 3b }

  condition:
    any of them
}