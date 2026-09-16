rule TTP_XOR_QUAD_CurrentVersionRun_4320 {
  strings:
    $key_4320 = { 10 4f [2] 34 41 [2] 1f 6d [2] 31 4f [2] 25 54 [2] 2a 4e [2] 34 53 [2] 36 52 [2] 2d 54 [2] 31 53 [2] 2d 7c }

  condition:
    any of them
}