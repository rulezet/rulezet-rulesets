rule TTP_XOR_QUAD_CurrentVersionRun_7f41 {
  strings:
    $key_7f41 = { 2c 2e [2] 08 20 [2] 23 0c [2] 0d 2e [2] 19 35 [2] 16 2f [2] 08 32 [2] 0a 33 [2] 11 35 [2] 0d 32 [2] 11 1d }

  condition:
    any of them
}