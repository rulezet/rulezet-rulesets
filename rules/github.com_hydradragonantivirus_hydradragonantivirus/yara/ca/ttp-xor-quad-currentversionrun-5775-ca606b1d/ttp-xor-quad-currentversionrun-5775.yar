rule TTP_XOR_QUAD_CurrentVersionRun_5775 {
  strings:
    $key_5775 = { 04 1a [2] 20 14 [2] 0b 38 [2] 25 1a [2] 31 01 [2] 3e 1b [2] 20 06 [2] 22 07 [2] 39 01 [2] 25 06 [2] 39 29 }

  condition:
    any of them
}