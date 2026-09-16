rule TTP_XOR_QUAD_CurrentVersionRun_0560 {
  strings:
    $key_0560 = { 56 0f [2] 72 01 [2] 59 2d [2] 77 0f [2] 63 14 [2] 6c 0e [2] 72 13 [2] 70 12 [2] 6b 14 [2] 77 13 [2] 6b 3c }

  condition:
    any of them
}