rule TTP_XOR_QUAD_CurrentVersionRun_3a75 {
  strings:
    $key_3a75 = { 69 1a [2] 4d 14 [2] 66 38 [2] 48 1a [2] 5c 01 [2] 53 1b [2] 4d 06 [2] 4f 07 [2] 54 01 [2] 48 06 [2] 54 29 }

  condition:
    any of them
}