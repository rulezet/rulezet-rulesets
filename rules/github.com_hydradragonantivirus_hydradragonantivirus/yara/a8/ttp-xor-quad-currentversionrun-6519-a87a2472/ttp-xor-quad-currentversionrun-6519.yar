rule TTP_XOR_QUAD_CurrentVersionRun_6519 {
  strings:
    $key_6519 = { 36 76 [2] 12 78 [2] 39 54 [2] 17 76 [2] 03 6d [2] 0c 77 [2] 12 6a [2] 10 6b [2] 0b 6d [2] 17 6a [2] 0b 45 }

  condition:
    any of them
}