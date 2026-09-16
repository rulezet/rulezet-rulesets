rule TTP_XOR_QUAD_CurrentVersionRun_3140 {
  strings:
    $key_3140 = { 62 2f [2] 46 21 [2] 6d 0d [2] 43 2f [2] 57 34 [2] 58 2e [2] 46 33 [2] 44 32 [2] 5f 34 [2] 43 33 [2] 5f 1c }

  condition:
    any of them
}