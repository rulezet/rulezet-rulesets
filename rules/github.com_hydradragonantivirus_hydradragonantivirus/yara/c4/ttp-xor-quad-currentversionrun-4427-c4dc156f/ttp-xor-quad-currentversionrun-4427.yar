rule TTP_XOR_QUAD_CurrentVersionRun_4427 {
  strings:
    $key_4427 = { 17 48 [2] 33 46 [2] 18 6a [2] 36 48 [2] 22 53 [2] 2d 49 [2] 33 54 [2] 31 55 [2] 2a 53 [2] 36 54 [2] 2a 7b }

  condition:
    any of them
}