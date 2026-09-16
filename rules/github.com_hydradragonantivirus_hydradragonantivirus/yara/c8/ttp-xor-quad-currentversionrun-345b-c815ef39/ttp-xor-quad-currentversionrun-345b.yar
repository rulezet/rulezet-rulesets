rule TTP_XOR_QUAD_CurrentVersionRun_345b {
  strings:
    $key_345b = { 67 34 [2] 43 3a [2] 68 16 [2] 46 34 [2] 52 2f [2] 5d 35 [2] 43 28 [2] 41 29 [2] 5a 2f [2] 46 28 [2] 5a 07 }

  condition:
    any of them
}