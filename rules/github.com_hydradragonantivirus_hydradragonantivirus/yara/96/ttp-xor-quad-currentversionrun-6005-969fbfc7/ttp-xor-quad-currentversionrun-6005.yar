rule TTP_XOR_QUAD_CurrentVersionRun_6005 {
  strings:
    $key_6005 = { 33 6a [2] 17 64 [2] 3c 48 [2] 12 6a [2] 06 71 [2] 09 6b [2] 17 76 [2] 15 77 [2] 0e 71 [2] 12 76 [2] 0e 59 }

  condition:
    any of them
}