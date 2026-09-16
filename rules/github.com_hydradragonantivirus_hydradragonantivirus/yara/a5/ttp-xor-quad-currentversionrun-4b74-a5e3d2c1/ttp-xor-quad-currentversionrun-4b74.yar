rule TTP_XOR_QUAD_CurrentVersionRun_4b74 {
  strings:
    $key_4b74 = { 18 1b [2] 3c 15 [2] 17 39 [2] 39 1b [2] 2d 00 [2] 22 1a [2] 3c 07 [2] 3e 06 [2] 25 00 [2] 39 07 [2] 25 28 }

  condition:
    any of them
}