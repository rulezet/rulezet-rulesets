rule TTP_XOR_QUAD_CurrentVersionRun_7f27 {
  strings:
    $key_7f27 = { 2c 48 [2] 08 46 [2] 23 6a [2] 0d 48 [2] 19 53 [2] 16 49 [2] 08 54 [2] 0a 55 [2] 11 53 [2] 0d 54 [2] 11 7b }

  condition:
    any of them
}