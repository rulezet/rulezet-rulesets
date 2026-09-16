rule TTP_XOR_QUAD_CurrentVersionRun_6048 {
  strings:
    $key_6048 = { 33 27 [2] 17 29 [2] 3c 05 [2] 12 27 [2] 06 3c [2] 09 26 [2] 17 3b [2] 15 3a [2] 0e 3c [2] 12 3b [2] 0e 14 }

  condition:
    any of them
}