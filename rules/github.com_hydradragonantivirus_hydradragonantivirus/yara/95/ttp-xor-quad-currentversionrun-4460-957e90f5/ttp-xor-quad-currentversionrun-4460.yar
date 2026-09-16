rule TTP_XOR_QUAD_CurrentVersionRun_4460 {
  strings:
    $key_4460 = { 17 0f [2] 33 01 [2] 18 2d [2] 36 0f [2] 22 14 [2] 2d 0e [2] 33 13 [2] 31 12 [2] 2a 14 [2] 36 13 [2] 2a 3c }

  condition:
    any of them
}