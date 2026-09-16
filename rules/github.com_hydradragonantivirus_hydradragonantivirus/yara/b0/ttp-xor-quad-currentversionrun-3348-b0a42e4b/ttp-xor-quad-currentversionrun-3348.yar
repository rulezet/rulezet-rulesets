rule TTP_XOR_QUAD_CurrentVersionRun_3348 {
  strings:
    $key_3348 = { 60 27 [2] 44 29 [2] 6f 05 [2] 41 27 [2] 55 3c [2] 5a 26 [2] 44 3b [2] 46 3a [2] 5d 3c [2] 41 3b [2] 5d 14 }

  condition:
    any of them
}