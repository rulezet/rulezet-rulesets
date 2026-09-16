rule TTP_XOR_QUAD_CurrentVersionRun_6824 {
  strings:
    $key_6824 = { 3b 4b [2] 1f 45 [2] 34 69 [2] 1a 4b [2] 0e 50 [2] 01 4a [2] 1f 57 [2] 1d 56 [2] 06 50 [2] 1a 57 [2] 06 78 }

  condition:
    any of them
}