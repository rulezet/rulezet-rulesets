rule TTP_XOR_QUAD_CurrentVersionRun_4450 {
  strings:
    $key_4450 = { 17 3f [2] 33 31 [2] 18 1d [2] 36 3f [2] 22 24 [2] 2d 3e [2] 33 23 [2] 31 22 [2] 2a 24 [2] 36 23 [2] 2a 0c }

  condition:
    any of them
}