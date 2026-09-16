rule TTP_XOR_QUAD_CurrentVersionRun_0444 {
  strings:
    $key_0444 = { 57 2b [2] 73 25 [2] 58 09 [2] 76 2b [2] 62 30 [2] 6d 2a [2] 73 37 [2] 71 36 [2] 6a 30 [2] 76 37 [2] 6a 18 }

  condition:
    any of them
}