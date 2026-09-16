rule TTP_XOR_QUAD_CurrentVersionRun_7c27 {
  strings:
    $key_7c27 = { 2f 48 [2] 0b 46 [2] 20 6a [2] 0e 48 [2] 1a 53 [2] 15 49 [2] 0b 54 [2] 09 55 [2] 12 53 [2] 0e 54 [2] 12 7b }

  condition:
    any of them
}