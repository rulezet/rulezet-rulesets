rule TTP_XOR_QUAD_CurrentVersionRun_5a7d {
  strings:
    $key_5a7d = { 09 12 [2] 2d 1c [2] 06 30 [2] 28 12 [2] 3c 09 [2] 33 13 [2] 2d 0e [2] 2f 0f [2] 34 09 [2] 28 0e [2] 34 21 }

  condition:
    any of them
}