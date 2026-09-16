rule TTP_XOR_QUAD_CurrentVersionRun_5a66 {
  strings:
    $key_5a66 = { 09 09 [2] 2d 07 [2] 06 2b [2] 28 09 [2] 3c 12 [2] 33 08 [2] 2d 15 [2] 2f 14 [2] 34 12 [2] 28 15 [2] 34 3a }

  condition:
    any of them
}