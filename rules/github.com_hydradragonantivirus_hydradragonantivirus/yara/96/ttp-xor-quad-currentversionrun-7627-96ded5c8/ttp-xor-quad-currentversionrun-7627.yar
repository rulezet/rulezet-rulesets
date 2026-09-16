rule TTP_XOR_QUAD_CurrentVersionRun_7627 {
  strings:
    $key_7627 = { 25 48 [2] 01 46 [2] 2a 6a [2] 04 48 [2] 10 53 [2] 1f 49 [2] 01 54 [2] 03 55 [2] 18 53 [2] 04 54 [2] 18 7b }

  condition:
    any of them
}