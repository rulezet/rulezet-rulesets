rule TTP_XOR_QUAD_CurrentVersionRun_5048 {
  strings:
    $key_5048 = { 03 27 [2] 27 29 [2] 0c 05 [2] 22 27 [2] 36 3c [2] 39 26 [2] 27 3b [2] 25 3a [2] 3e 3c [2] 22 3b [2] 3e 14 }

  condition:
    any of them
}