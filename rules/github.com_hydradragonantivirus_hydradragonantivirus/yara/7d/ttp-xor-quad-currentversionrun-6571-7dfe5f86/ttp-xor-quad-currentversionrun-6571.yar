rule TTP_XOR_QUAD_CurrentVersionRun_6571 {
  strings:
    $key_6571 = { 36 1e [2] 12 10 [2] 39 3c [2] 17 1e [2] 03 05 [2] 0c 1f [2] 12 02 [2] 10 03 [2] 0b 05 [2] 17 02 [2] 0b 2d }

  condition:
    any of them
}