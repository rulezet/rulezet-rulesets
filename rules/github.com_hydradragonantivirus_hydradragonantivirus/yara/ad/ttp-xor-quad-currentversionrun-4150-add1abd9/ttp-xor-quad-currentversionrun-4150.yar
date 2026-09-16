rule TTP_XOR_QUAD_CurrentVersionRun_4150 {
  strings:
    $key_4150 = { 12 3f [2] 36 31 [2] 1d 1d [2] 33 3f [2] 27 24 [2] 28 3e [2] 36 23 [2] 34 22 [2] 2f 24 [2] 33 23 [2] 2f 0c }

  condition:
    any of them
}