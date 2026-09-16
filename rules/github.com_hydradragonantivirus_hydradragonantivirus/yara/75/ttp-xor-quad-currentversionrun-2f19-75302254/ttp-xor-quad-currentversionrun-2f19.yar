rule TTP_XOR_QUAD_CurrentVersionRun_2f19 {
  strings:
    $key_2f19 = { 7c 76 [2] 58 78 [2] 73 54 [2] 5d 76 [2] 49 6d [2] 46 77 [2] 58 6a [2] 5a 6b [2] 41 6d [2] 5d 6a [2] 41 45 }

  condition:
    any of them
}