rule TTP_XOR_QUAD_CurrentVersionRun_1169 {
  strings:
    $key_1169 = { 42 06 [2] 66 08 [2] 4d 24 [2] 63 06 [2] 77 1d [2] 78 07 [2] 66 1a [2] 64 1b [2] 7f 1d [2] 63 1a [2] 7f 35 }

  condition:
    any of them
}