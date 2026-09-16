rule TTP_XOR_QUAD_CurrentVersionRun_4e48 {
  strings:
    $key_4e48 = { 1d 27 [2] 39 29 [2] 12 05 [2] 3c 27 [2] 28 3c [2] 27 26 [2] 39 3b [2] 3b 3a [2] 20 3c [2] 3c 3b [2] 20 14 }

  condition:
    any of them
}