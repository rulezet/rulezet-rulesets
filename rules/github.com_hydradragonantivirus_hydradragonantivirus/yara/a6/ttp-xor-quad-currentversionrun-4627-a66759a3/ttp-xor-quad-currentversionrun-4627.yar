rule TTP_XOR_QUAD_CurrentVersionRun_4627 {
  strings:
    $key_4627 = { 15 48 [2] 31 46 [2] 1a 6a [2] 34 48 [2] 20 53 [2] 2f 49 [2] 31 54 [2] 33 55 [2] 28 53 [2] 34 54 [2] 28 7b }

  condition:
    any of them
}