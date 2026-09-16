rule TTP_XOR_QUAD_CurrentVersionRun_0760 {
  strings:
    $key_0760 = { 54 0f [2] 70 01 [2] 5b 2d [2] 75 0f [2] 61 14 [2] 6e 0e [2] 70 13 [2] 72 12 [2] 69 14 [2] 75 13 [2] 69 3c }

  condition:
    any of them
}