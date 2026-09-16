rule TTP_XOR_QUAD_CurrentVersionRun_4b27 {
  strings:
    $key_4b27 = { 18 48 [2] 3c 46 [2] 17 6a [2] 39 48 [2] 2d 53 [2] 22 49 [2] 3c 54 [2] 3e 55 [2] 25 53 [2] 39 54 [2] 25 7b }

  condition:
    any of them
}