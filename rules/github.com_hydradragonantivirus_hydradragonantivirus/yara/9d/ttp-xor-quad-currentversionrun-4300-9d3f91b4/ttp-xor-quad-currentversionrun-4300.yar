rule TTP_XOR_QUAD_CurrentVersionRun_4300 {
  strings:
    $key_4300 = { 10 6f [2] 34 61 [2] 1f 4d [2] 31 6f [2] 25 74 [2] 2a 6e [2] 34 73 [2] 36 72 [2] 2d 74 [2] 31 73 [2] 2d 5c }

  condition:
    any of them
}