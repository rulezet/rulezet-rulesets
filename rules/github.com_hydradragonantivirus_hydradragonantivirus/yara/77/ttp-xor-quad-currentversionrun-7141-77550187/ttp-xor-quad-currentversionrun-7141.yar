rule TTP_XOR_QUAD_CurrentVersionRun_7141 {
  strings:
    $key_7141 = { 22 2e [2] 06 20 [2] 2d 0c [2] 03 2e [2] 17 35 [2] 18 2f [2] 06 32 [2] 04 33 [2] 1f 35 [2] 03 32 [2] 1f 1d }

  condition:
    any of them
}