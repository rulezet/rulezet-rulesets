rule TTP_XOR_QUAD_CurrentVersionRun_6d75 {
  strings:
    $key_6d75 = { 3e 1a [2] 1a 14 [2] 31 38 [2] 1f 1a [2] 0b 01 [2] 04 1b [2] 1a 06 [2] 18 07 [2] 03 01 [2] 1f 06 [2] 03 29 }

  condition:
    any of them
}