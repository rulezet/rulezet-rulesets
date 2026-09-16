rule TTP_XOR_QUAD_CurrentVersionRun_6727 {
  strings:
    $key_6727 = { 34 48 [2] 10 46 [2] 3b 6a [2] 15 48 [2] 01 53 [2] 0e 49 [2] 10 54 [2] 12 55 [2] 09 53 [2] 15 54 [2] 09 7b }

  condition:
    any of them
}