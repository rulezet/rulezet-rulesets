rule TTP_XOR_QUAD_CurrentVersionRun_7369 {
  strings:
    $key_7369 = { 20 06 [2] 04 08 [2] 2f 24 [2] 01 06 [2] 15 1d [2] 1a 07 [2] 04 1a [2] 06 1b [2] 1d 1d [2] 01 1a [2] 1d 35 }

  condition:
    any of them
}