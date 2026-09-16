rule TTP_XOR_QUAD_CurrentVersionRun_7975 {
  strings:
    $key_7975 = { 2a 1a [2] 0e 14 [2] 25 38 [2] 0b 1a [2] 1f 01 [2] 10 1b [2] 0e 06 [2] 0c 07 [2] 17 01 [2] 0b 06 [2] 17 29 }

  condition:
    any of them
}