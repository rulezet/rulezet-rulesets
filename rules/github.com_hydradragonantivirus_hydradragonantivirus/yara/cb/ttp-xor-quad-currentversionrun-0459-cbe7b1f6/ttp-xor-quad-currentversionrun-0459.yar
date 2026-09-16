rule TTP_XOR_QUAD_CurrentVersionRun_0459 {
  strings:
    $key_0459 = { 57 36 [2] 73 38 [2] 58 14 [2] 76 36 [2] 62 2d [2] 6d 37 [2] 73 2a [2] 71 2b [2] 6a 2d [2] 76 2a [2] 6a 05 }

  condition:
    any of them
}