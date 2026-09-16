rule TTP_XOR_QUAD_CurrentVersionRun_3560 {
  strings:
    $key_3560 = { 66 0f [2] 42 01 [2] 69 2d [2] 47 0f [2] 53 14 [2] 5c 0e [2] 42 13 [2] 40 12 [2] 5b 14 [2] 47 13 [2] 5b 3c }

  condition:
    any of them
}