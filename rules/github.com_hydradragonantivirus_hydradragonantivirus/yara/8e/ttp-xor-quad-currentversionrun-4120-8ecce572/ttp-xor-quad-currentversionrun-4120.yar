rule TTP_XOR_QUAD_CurrentVersionRun_4120 {
  strings:
    $key_4120 = { 12 4f [2] 36 41 [2] 1d 6d [2] 33 4f [2] 27 54 [2] 28 4e [2] 36 53 [2] 34 52 [2] 2f 54 [2] 33 53 [2] 2f 7c }

  condition:
    any of them
}