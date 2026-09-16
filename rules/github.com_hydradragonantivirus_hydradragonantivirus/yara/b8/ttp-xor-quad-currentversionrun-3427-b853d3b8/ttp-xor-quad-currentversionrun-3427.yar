rule TTP_XOR_QUAD_CurrentVersionRun_3427 {
  strings:
    $key_3427 = { 67 48 [2] 43 46 [2] 68 6a [2] 46 48 [2] 52 53 [2] 5d 49 [2] 43 54 [2] 41 55 [2] 5a 53 [2] 46 54 [2] 5a 7b }

  condition:
    any of them
}