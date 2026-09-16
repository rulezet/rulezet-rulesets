rule TTP_XOR_QUAD_CurrentVersionRun_0e69 {
  strings:
    $key_0e69 = { 5d 06 [2] 79 08 [2] 52 24 [2] 7c 06 [2] 68 1d [2] 67 07 [2] 79 1a [2] 7b 1b [2] 60 1d [2] 7c 1a [2] 60 35 }

  condition:
    any of them
}