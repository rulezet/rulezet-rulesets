rule TTP_XOR_QUAD_CurrentVersionRun_7126 {
  strings:
    $key_7126 = { 22 49 [2] 06 47 [2] 2d 6b [2] 03 49 [2] 17 52 [2] 18 48 [2] 06 55 [2] 04 54 [2] 1f 52 [2] 03 55 [2] 1f 7a }

  condition:
    any of them
}