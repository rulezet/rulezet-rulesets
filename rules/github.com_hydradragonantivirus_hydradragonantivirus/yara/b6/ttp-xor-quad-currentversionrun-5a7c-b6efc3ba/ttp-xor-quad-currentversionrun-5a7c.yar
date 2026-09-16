rule TTP_XOR_QUAD_CurrentVersionRun_5a7c {
  strings:
    $key_5a7c = { 09 13 [2] 2d 1d [2] 06 31 [2] 28 13 [2] 3c 08 [2] 33 12 [2] 2d 0f [2] 2f 0e [2] 34 08 [2] 28 0f [2] 34 20 }

  condition:
    any of them
}