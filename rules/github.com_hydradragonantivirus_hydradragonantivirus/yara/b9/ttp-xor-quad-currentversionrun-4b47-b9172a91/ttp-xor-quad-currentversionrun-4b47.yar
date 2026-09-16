rule TTP_XOR_QUAD_CurrentVersionRun_4b47 {
  strings:
    $key_4b47 = { 18 28 [2] 3c 26 [2] 17 0a [2] 39 28 [2] 2d 33 [2] 22 29 [2] 3c 34 [2] 3e 35 [2] 25 33 [2] 39 34 [2] 25 1b }

  condition:
    any of them
}