rule TTP_XOR_QUAD_CurrentVersionRun_7669 {
  strings:
    $key_7669 = { 25 06 [2] 01 08 [2] 2a 24 [2] 04 06 [2] 10 1d [2] 1f 07 [2] 01 1a [2] 03 1b [2] 18 1d [2] 04 1a [2] 18 35 }

  condition:
    any of them
}