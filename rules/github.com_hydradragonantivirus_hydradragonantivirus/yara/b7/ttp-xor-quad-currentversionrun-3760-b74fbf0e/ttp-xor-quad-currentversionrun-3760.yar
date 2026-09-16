rule TTP_XOR_QUAD_CurrentVersionRun_3760 {
  strings:
    $key_3760 = { 64 0f [2] 40 01 [2] 6b 2d [2] 45 0f [2] 51 14 [2] 5e 0e [2] 40 13 [2] 42 12 [2] 59 14 [2] 45 13 [2] 59 3c }

  condition:
    any of them
}