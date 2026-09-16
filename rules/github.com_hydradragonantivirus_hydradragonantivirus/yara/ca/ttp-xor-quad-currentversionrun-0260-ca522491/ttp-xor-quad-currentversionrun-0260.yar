rule TTP_XOR_QUAD_CurrentVersionRun_0260 {
  strings:
    $key_0260 = { 51 0f [2] 75 01 [2] 5e 2d [2] 70 0f [2] 64 14 [2] 6b 0e [2] 75 13 [2] 77 12 [2] 6c 14 [2] 70 13 [2] 6c 3c }

  condition:
    any of them
}