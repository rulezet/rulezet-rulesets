rule TTP_XOR_QUAD_CurrentVersionRun_5f31 {
  strings:
    $key_5f31 = { 0c 5e [2] 28 50 [2] 03 7c [2] 2d 5e [2] 39 45 [2] 36 5f [2] 28 42 [2] 2a 43 [2] 31 45 [2] 2d 42 [2] 31 6d }

  condition:
    any of them
}