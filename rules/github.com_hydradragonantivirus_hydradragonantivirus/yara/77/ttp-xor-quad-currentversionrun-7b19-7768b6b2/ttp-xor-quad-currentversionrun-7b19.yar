rule TTP_XOR_QUAD_CurrentVersionRun_7b19 {
  strings:
    $key_7b19 = { 28 76 [2] 0c 78 [2] 27 54 [2] 09 76 [2] 1d 6d [2] 12 77 [2] 0c 6a [2] 0e 6b [2] 15 6d [2] 09 6a [2] 15 45 }

  condition:
    any of them
}