rule TTP_XOR_QUAD_CurrentVersionRun_7675 {
  strings:
    $key_7675 = { 25 1a [2] 01 14 [2] 2a 38 [2] 04 1a [2] 10 01 [2] 1f 1b [2] 01 06 [2] 03 07 [2] 18 01 [2] 04 06 [2] 18 29 }

  condition:
    any of them
}