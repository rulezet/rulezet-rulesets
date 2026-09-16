rule TTP_XOR_QUAD_CurrentVersionRun_3561 {
  strings:
    $key_3561 = { 66 0e [2] 42 00 [2] 69 2c [2] 47 0e [2] 53 15 [2] 5c 0f [2] 42 12 [2] 40 13 [2] 5b 15 [2] 47 12 [2] 5b 3d }

  condition:
    any of them
}