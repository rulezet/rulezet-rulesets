rule TTP_XOR_QUAD_CurrentVersionRun_2e61 {
  strings:
    $key_2e61 = { 7d 0e [2] 59 00 [2] 72 2c [2] 5c 0e [2] 48 15 [2] 47 0f [2] 59 12 [2] 5b 13 [2] 40 15 [2] 5c 12 [2] 40 3d }

  condition:
    any of them
}