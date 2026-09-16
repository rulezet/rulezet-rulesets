rule TTP_XOR_QUAD_CurrentVersionRun_2367 {
  strings:
    $key_2367 = { 70 08 [2] 54 06 [2] 7f 2a [2] 51 08 [2] 45 13 [2] 4a 09 [2] 54 14 [2] 56 15 [2] 4d 13 [2] 51 14 [2] 4d 3b }

  condition:
    any of them
}