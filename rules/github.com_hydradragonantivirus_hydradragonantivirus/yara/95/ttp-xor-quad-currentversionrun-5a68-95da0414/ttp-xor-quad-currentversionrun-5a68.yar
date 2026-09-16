rule TTP_XOR_QUAD_CurrentVersionRun_5a68 {
  strings:
    $key_5a68 = { 09 07 [2] 2d 09 [2] 06 25 [2] 28 07 [2] 3c 1c [2] 33 06 [2] 2d 1b [2] 2f 1a [2] 34 1c [2] 28 1b [2] 34 34 }

  condition:
    any of them
}