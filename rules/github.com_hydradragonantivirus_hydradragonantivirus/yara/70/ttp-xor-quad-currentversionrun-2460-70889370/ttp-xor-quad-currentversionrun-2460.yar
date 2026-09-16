rule TTP_XOR_QUAD_CurrentVersionRun_2460 {
  strings:
    $key_2460 = { 77 0f [2] 53 01 [2] 78 2d [2] 56 0f [2] 42 14 [2] 4d 0e [2] 53 13 [2] 51 12 [2] 4a 14 [2] 56 13 [2] 4a 3c }

  condition:
    any of them
}