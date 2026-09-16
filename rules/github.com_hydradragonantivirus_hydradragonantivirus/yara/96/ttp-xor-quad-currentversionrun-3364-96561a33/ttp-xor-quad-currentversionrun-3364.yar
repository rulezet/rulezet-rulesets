rule TTP_XOR_QUAD_CurrentVersionRun_3364 {
  strings:
    $key_3364 = { 60 0b [2] 44 05 [2] 6f 29 [2] 41 0b [2] 55 10 [2] 5a 0a [2] 44 17 [2] 46 16 [2] 5d 10 [2] 41 17 [2] 5d 38 }

  condition:
    any of them
}