rule TTP_XOR_QUAD_CurrentVersionRun_6869 {
  strings:
    $key_6869 = { 3b 06 [2] 1f 08 [2] 34 24 [2] 1a 06 [2] 0e 1d [2] 01 07 [2] 1f 1a [2] 1d 1b [2] 06 1d [2] 1a 1a [2] 06 35 }

  condition:
    any of them
}