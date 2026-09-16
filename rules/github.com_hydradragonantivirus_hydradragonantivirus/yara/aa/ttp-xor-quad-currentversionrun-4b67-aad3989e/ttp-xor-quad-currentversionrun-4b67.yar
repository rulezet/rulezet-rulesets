rule TTP_XOR_QUAD_CurrentVersionRun_4b67 {
  strings:
    $key_4b67 = { 18 08 [2] 3c 06 [2] 17 2a [2] 39 08 [2] 2d 13 [2] 22 09 [2] 3c 14 [2] 3e 15 [2] 25 13 [2] 39 14 [2] 25 3b }

  condition:
    any of them
}