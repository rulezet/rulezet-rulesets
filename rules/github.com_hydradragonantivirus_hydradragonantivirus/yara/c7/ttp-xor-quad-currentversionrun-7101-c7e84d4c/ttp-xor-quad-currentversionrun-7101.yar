rule TTP_XOR_QUAD_CurrentVersionRun_7101 {
  strings:
    $key_7101 = { 22 6e [2] 06 60 [2] 2d 4c [2] 03 6e [2] 17 75 [2] 18 6f [2] 06 72 [2] 04 73 [2] 1f 75 [2] 03 72 [2] 1f 5d }

  condition:
    any of them
}