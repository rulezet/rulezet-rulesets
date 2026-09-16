rule TTP_XOR_QUAD_CurrentVersionRun_0b69 {
  strings:
    $key_0b69 = { 58 06 [2] 7c 08 [2] 57 24 [2] 79 06 [2] 6d 1d [2] 62 07 [2] 7c 1a [2] 7e 1b [2] 65 1d [2] 79 1a [2] 65 35 }

  condition:
    any of them
}