rule TTP_XOR_QUAD_CurrentVersionRun_2455 {
  strings:
    $key_2455 = { 77 3a [2] 53 34 [2] 78 18 [2] 56 3a [2] 42 21 [2] 4d 3b [2] 53 26 [2] 51 27 [2] 4a 21 [2] 56 26 [2] 4a 09 }

  condition:
    any of them
}