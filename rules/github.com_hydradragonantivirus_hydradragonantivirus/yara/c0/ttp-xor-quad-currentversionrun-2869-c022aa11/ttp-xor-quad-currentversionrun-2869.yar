rule TTP_XOR_QUAD_CurrentVersionRun_2869 {
  strings:
    $key_2869 = { 7b 06 [2] 5f 08 [2] 74 24 [2] 5a 06 [2] 4e 1d [2] 41 07 [2] 5f 1a [2] 5d 1b [2] 46 1d [2] 5a 1a [2] 46 35 }

  condition:
    any of them
}