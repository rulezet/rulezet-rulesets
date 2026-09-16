rule TTP_XOR_QUAD_CurrentVersionRun_2364 {
  strings:
    $key_2364 = { 70 0b [2] 54 05 [2] 7f 29 [2] 51 0b [2] 45 10 [2] 4a 0a [2] 54 17 [2] 56 16 [2] 4d 10 [2] 51 17 [2] 4d 38 }

  condition:
    any of them
}