rule TTP_XOR_QUAD_CurrentVersionRun_7150 {
  strings:
    $key_7150 = { 22 3f [2] 06 31 [2] 2d 1d [2] 03 3f [2] 17 24 [2] 18 3e [2] 06 23 [2] 04 22 [2] 1f 24 [2] 03 23 [2] 1f 0c }

  condition:
    any of them
}