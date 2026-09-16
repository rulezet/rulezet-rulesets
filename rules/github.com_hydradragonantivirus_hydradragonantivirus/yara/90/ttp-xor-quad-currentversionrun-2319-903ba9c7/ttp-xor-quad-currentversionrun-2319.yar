rule TTP_XOR_QUAD_CurrentVersionRun_2319 {
  strings:
    $key_2319 = { 70 76 [2] 54 78 [2] 7f 54 [2] 51 76 [2] 45 6d [2] 4a 77 [2] 54 6a [2] 56 6b [2] 4d 6d [2] 51 6a [2] 4d 45 }

  condition:
    any of them
}