rule TTP_XOR_QUAD_CurrentVersionRun_1160 {
  strings:
    $key_1160 = { 42 0f [2] 66 01 [2] 4d 2d [2] 63 0f [2] 77 14 [2] 78 0e [2] 66 13 [2] 64 12 [2] 7f 14 [2] 63 13 [2] 7f 3c }

  condition:
    any of them
}