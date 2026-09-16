rule TTP_XOR_QUAD_CurrentVersionRun_6871 {
  strings:
    $key_6871 = { 3b 1e [2] 1f 10 [2] 34 3c [2] 1a 1e [2] 0e 05 [2] 01 1f [2] 1f 02 [2] 1d 03 [2] 06 05 [2] 1a 02 [2] 06 2d }

  condition:
    any of them
}