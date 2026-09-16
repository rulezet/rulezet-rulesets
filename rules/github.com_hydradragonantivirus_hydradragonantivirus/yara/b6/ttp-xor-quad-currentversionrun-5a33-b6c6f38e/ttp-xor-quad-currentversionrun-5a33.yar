rule TTP_XOR_QUAD_CurrentVersionRun_5a33 {
  strings:
    $key_5a33 = { 09 5c [2] 2d 52 [2] 06 7e [2] 28 5c [2] 3c 47 [2] 33 5d [2] 2d 40 [2] 2f 41 [2] 34 47 [2] 28 40 [2] 34 6f }

  condition:
    any of them
}