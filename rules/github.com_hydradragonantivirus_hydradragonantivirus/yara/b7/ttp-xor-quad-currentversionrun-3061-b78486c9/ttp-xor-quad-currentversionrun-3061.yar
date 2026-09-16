rule TTP_XOR_QUAD_CurrentVersionRun_3061 {
  strings:
    $key_3061 = { 63 0e [2] 47 00 [2] 6c 2c [2] 42 0e [2] 56 15 [2] 59 0f [2] 47 12 [2] 45 13 [2] 5e 15 [2] 42 12 [2] 5e 3d }

  condition:
    any of them
}