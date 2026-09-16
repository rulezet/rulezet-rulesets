rule TTP_XOR_QUAD_CurrentVersionRun_6050 {
  strings:
    $key_6050 = { 33 3f [2] 17 31 [2] 3c 1d [2] 12 3f [2] 06 24 [2] 09 3e [2] 17 23 [2] 15 22 [2] 0e 24 [2] 12 23 [2] 0e 0c }

  condition:
    any of them
}