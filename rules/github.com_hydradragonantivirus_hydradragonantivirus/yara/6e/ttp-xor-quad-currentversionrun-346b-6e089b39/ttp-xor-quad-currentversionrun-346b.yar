rule TTP_XOR_QUAD_CurrentVersionRun_346b {
  strings:
    $key_346b = { 67 04 [2] 43 0a [2] 68 26 [2] 46 04 [2] 52 1f [2] 5d 05 [2] 43 18 [2] 41 19 [2] 5a 1f [2] 46 18 [2] 5a 37 }

  condition:
    any of them
}