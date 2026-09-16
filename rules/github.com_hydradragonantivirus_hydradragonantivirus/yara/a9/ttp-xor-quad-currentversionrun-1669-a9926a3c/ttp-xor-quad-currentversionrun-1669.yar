rule TTP_XOR_QUAD_CurrentVersionRun_1669 {
  strings:
    $key_1669 = { 45 06 [2] 61 08 [2] 4a 24 [2] 64 06 [2] 70 1d [2] 7f 07 [2] 61 1a [2] 63 1b [2] 78 1d [2] 64 1a [2] 78 35 }

  condition:
    any of them
}