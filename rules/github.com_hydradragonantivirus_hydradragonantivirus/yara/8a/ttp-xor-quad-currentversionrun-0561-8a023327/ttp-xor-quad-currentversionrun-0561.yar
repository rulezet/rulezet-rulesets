rule TTP_XOR_QUAD_CurrentVersionRun_0561 {
  strings:
    $key_0561 = { 56 0e [2] 72 00 [2] 59 2c [2] 77 0e [2] 63 15 [2] 6c 0f [2] 72 12 [2] 70 13 [2] 6b 15 [2] 77 12 [2] 6b 3d }

  condition:
    any of them
}