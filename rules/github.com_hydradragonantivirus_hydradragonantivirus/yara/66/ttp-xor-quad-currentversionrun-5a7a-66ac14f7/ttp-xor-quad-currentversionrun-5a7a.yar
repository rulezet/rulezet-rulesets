rule TTP_XOR_QUAD_CurrentVersionRun_5a7a {
  strings:
    $key_5a7a = { 09 15 [2] 2d 1b [2] 06 37 [2] 28 15 [2] 3c 0e [2] 33 14 [2] 2d 09 [2] 2f 08 [2] 34 0e [2] 28 09 [2] 34 26 }

  condition:
    any of them
}