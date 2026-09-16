rule TTP_XOR_QUAD_CurrentVersionRun_2378 {
  strings:
    $key_2378 = { 70 17 [2] 54 19 [2] 7f 35 [2] 51 17 [2] 45 0c [2] 4a 16 [2] 54 0b [2] 56 0a [2] 4d 0c [2] 51 0b [2] 4d 24 }

  condition:
    any of them
}