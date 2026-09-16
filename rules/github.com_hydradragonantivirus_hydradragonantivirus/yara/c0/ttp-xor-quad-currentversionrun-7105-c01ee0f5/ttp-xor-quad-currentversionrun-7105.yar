rule TTP_XOR_QUAD_CurrentVersionRun_7105 {
  strings:
    $key_7105 = { 22 6a [2] 06 64 [2] 2d 48 [2] 03 6a [2] 17 71 [2] 18 6b [2] 06 76 [2] 04 77 [2] 1f 71 [2] 03 76 [2] 1f 59 }

  condition:
    any of them
}