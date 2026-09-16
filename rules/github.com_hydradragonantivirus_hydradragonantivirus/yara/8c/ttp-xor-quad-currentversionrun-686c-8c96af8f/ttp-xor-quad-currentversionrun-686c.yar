rule TTP_XOR_QUAD_CurrentVersionRun_686c {
  strings:
    $key_686c = { 3b 03 [2] 1f 0d [2] 34 21 [2] 1a 03 [2] 0e 18 [2] 01 02 [2] 1f 1f [2] 1d 1e [2] 06 18 [2] 1a 1f [2] 06 30 }

  condition:
    any of them
}