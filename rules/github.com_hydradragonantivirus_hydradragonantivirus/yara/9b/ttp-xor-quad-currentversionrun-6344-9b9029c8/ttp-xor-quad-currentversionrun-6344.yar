rule TTP_XOR_QUAD_CurrentVersionRun_6344 {
  strings:
    $key_6344 = { 30 2b [2] 14 25 [2] 3f 09 [2] 11 2b [2] 05 30 [2] 0a 2a [2] 14 37 [2] 16 36 [2] 0d 30 [2] 11 37 [2] 0d 18 }

  condition:
    any of them
}