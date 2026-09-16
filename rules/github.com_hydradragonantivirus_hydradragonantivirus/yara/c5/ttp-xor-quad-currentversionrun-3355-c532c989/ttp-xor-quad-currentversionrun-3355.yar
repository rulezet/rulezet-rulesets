rule TTP_XOR_QUAD_CurrentVersionRun_3355 {
  strings:
    $key_3355 = { 60 3a [2] 44 34 [2] 6f 18 [2] 41 3a [2] 55 21 [2] 5a 3b [2] 44 26 [2] 46 27 [2] 5d 21 [2] 41 26 [2] 5d 09 }

  condition:
    any of them
}