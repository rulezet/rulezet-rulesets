rule TTP_XOR_QUAD_CurrentVersionRun_7144 {
  strings:
    $key_7144 = { 22 2b [2] 06 25 [2] 2d 09 [2] 03 2b [2] 17 30 [2] 18 2a [2] 06 37 [2] 04 36 [2] 1f 30 [2] 03 37 [2] 1f 18 }

  condition:
    any of them
}