rule TTP_XOR_QUAD_CurrentVersionRun_1a69 {
  strings:
    $key_1a69 = { 49 06 [2] 6d 08 [2] 46 24 [2] 68 06 [2] 7c 1d [2] 73 07 [2] 6d 1a [2] 6f 1b [2] 74 1d [2] 68 1a [2] 74 35 }

  condition:
    any of them
}