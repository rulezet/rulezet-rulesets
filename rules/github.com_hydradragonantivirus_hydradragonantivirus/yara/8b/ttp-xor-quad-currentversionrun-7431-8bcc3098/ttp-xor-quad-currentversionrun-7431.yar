rule TTP_XOR_QUAD_CurrentVersionRun_7431 {
  strings:
    $key_7431 = { 27 5e [2] 03 50 [2] 28 7c [2] 06 5e [2] 12 45 [2] 1d 5f [2] 03 42 [2] 01 43 [2] 1a 45 [2] 06 42 [2] 1a 6d }

  condition:
    any of them
}