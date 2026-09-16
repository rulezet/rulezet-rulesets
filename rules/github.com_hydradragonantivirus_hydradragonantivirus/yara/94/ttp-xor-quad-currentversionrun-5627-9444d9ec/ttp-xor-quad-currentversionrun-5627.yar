rule TTP_XOR_QUAD_CurrentVersionRun_5627 {
  strings:
    $key_5627 = { 05 48 [2] 21 46 [2] 0a 6a [2] 24 48 [2] 30 53 [2] 3f 49 [2] 21 54 [2] 23 55 [2] 38 53 [2] 24 54 [2] 38 7b }

  condition:
    any of them
}