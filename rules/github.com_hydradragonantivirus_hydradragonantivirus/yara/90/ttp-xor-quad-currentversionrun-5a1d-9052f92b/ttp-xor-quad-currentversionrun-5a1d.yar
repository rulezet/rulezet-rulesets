rule TTP_XOR_QUAD_CurrentVersionRun_5a1d {
  strings:
    $key_5a1d = { 09 72 [2] 2d 7c [2] 06 50 [2] 28 72 [2] 3c 69 [2] 33 73 [2] 2d 6e [2] 2f 6f [2] 34 69 [2] 28 6e [2] 34 41 }

  condition:
    any of them
}