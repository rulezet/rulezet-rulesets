rule TTP_XOR_QUAD_CurrentVersionRun_7116 {
  strings:
    $key_7116 = { 22 79 [2] 06 77 [2] 2d 5b [2] 03 79 [2] 17 62 [2] 18 78 [2] 06 65 [2] 04 64 [2] 1f 62 [2] 03 65 [2] 1f 4a }

  condition:
    any of them
}