rule TTP_XOR_QUAD_CurrentVersionRun_5619 {
  strings:
    $key_5619 = { 05 76 [2] 21 78 [2] 0a 54 [2] 24 76 [2] 30 6d [2] 3f 77 [2] 21 6a [2] 23 6b [2] 38 6d [2] 24 6a [2] 38 45 }

  condition:
    any of them
}