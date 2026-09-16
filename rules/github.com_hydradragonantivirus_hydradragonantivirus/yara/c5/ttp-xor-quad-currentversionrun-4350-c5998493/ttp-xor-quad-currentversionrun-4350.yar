rule TTP_XOR_QUAD_CurrentVersionRun_4350 {
  strings:
    $key_4350 = { 10 3f [2] 34 31 [2] 1f 1d [2] 31 3f [2] 25 24 [2] 2a 3e [2] 34 23 [2] 36 22 [2] 2d 24 [2] 31 23 [2] 2d 0c }

  condition:
    any of them
}