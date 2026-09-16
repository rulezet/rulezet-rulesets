rule TTP_XOR_QUAD_CurrentVersionRun_5a41 {
  strings:
    $key_5a41 = { 09 2e [2] 2d 20 [2] 06 0c [2] 28 2e [2] 3c 35 [2] 33 2f [2] 2d 32 [2] 2f 33 [2] 34 35 [2] 28 32 [2] 34 1d }

  condition:
    any of them
}