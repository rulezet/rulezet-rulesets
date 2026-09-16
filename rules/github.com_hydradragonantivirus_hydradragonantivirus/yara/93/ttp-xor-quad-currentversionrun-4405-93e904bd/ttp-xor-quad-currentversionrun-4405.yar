rule TTP_XOR_QUAD_CurrentVersionRun_4405 {
  strings:
    $key_4405 = { 17 6a [2] 33 64 [2] 18 48 [2] 36 6a [2] 22 71 [2] 2d 6b [2] 33 76 [2] 31 77 [2] 2a 71 [2] 36 76 [2] 2a 59 }

  condition:
    any of them
}