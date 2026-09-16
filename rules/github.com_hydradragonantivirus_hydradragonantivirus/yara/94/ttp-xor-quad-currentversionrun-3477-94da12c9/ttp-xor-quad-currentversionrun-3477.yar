rule TTP_XOR_QUAD_CurrentVersionRun_3477 {
  strings:
    $key_3477 = { 67 18 [2] 43 16 [2] 68 3a [2] 46 18 [2] 52 03 [2] 5d 19 [2] 43 04 [2] 41 05 [2] 5a 03 [2] 46 04 [2] 5a 2b }

  condition:
    any of them
}