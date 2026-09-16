rule TTP_XOR_QUAD_CurrentVersionRun_2450 {
  strings:
    $key_2450 = { 77 3f [2] 53 31 [2] 78 1d [2] 56 3f [2] 42 24 [2] 4d 3e [2] 53 23 [2] 51 22 [2] 4a 24 [2] 56 23 [2] 4a 0c }

  condition:
    any of them
}