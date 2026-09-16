rule TTP_XOR_QUAD_CurrentVersionRun_0348 {
  strings:
    $key_0348 = { 50 27 [2] 74 29 [2] 5f 05 [2] 71 27 [2] 65 3c [2] 6a 26 [2] 74 3b [2] 76 3a [2] 6d 3c [2] 71 3b [2] 6d 14 }

  condition:
    any of them
}