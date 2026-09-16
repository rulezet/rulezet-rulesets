rule TTP_XOR_QUAD_CurrentVersionRun_4b66 {
  strings:
    $key_4b66 = { 18 09 [2] 3c 07 [2] 17 2b [2] 39 09 [2] 2d 12 [2] 22 08 [2] 3c 15 [2] 3e 14 [2] 25 12 [2] 39 15 [2] 25 3a }

  condition:
    any of them
}