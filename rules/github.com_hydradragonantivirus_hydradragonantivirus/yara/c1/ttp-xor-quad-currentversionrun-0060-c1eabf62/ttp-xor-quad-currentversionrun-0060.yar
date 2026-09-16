rule TTP_XOR_QUAD_CurrentVersionRun_0060 {
  strings:
    $key_0060 = { 53 0f [2] 77 01 [2] 5c 2d [2] 72 0f [2] 66 14 [2] 69 0e [2] 77 13 [2] 75 12 [2] 6e 14 [2] 72 13 [2] 6e 3c }

  condition:
    any of them
}