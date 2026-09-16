rule TTP_XOR_QUAD_CurrentVersionRun_6f27 {
  strings:
    $key_6f27 = { 3c 48 [2] 18 46 [2] 33 6a [2] 1d 48 [2] 09 53 [2] 06 49 [2] 18 54 [2] 1a 55 [2] 01 53 [2] 1d 54 [2] 01 7b }

  condition:
    any of them
}