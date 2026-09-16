rule TTP_XOR_QUAD_CurrentVersionRun_711d {
  strings:
    $key_711d = { 22 72 [2] 06 7c [2] 2d 50 [2] 03 72 [2] 17 69 [2] 18 73 [2] 06 6e [2] 04 6f [2] 1f 69 [2] 03 6e [2] 1f 41 }

  condition:
    any of them
}