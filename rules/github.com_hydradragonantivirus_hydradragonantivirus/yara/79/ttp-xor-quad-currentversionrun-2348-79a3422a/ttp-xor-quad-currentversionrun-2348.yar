rule TTP_XOR_QUAD_CurrentVersionRun_2348 {
  strings:
    $key_2348 = { 70 27 [2] 54 29 [2] 7f 05 [2] 51 27 [2] 45 3c [2] 4a 26 [2] 54 3b [2] 56 3a [2] 4d 3c [2] 51 3b [2] 4d 14 }

  condition:
    any of them
}