rule TTP_XOR_QUAD_CurrentVersionRun_2875 {
  strings:
    $key_2875 = { 7b 1a [2] 5f 14 [2] 74 38 [2] 5a 1a [2] 4e 01 [2] 41 1b [2] 5f 06 [2] 5d 07 [2] 46 01 [2] 5a 06 [2] 46 29 }

  condition:
    any of them
}