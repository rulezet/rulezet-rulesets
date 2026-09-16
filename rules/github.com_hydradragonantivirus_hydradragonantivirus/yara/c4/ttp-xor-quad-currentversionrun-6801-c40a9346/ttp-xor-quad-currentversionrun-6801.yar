rule TTP_XOR_QUAD_CurrentVersionRun_6801 {
  strings:
    $key_6801 = { 3b 6e [2] 1f 60 [2] 34 4c [2] 1a 6e [2] 0e 75 [2] 01 6f [2] 1f 72 [2] 1d 73 [2] 06 75 [2] 1a 72 [2] 06 5d }

  condition:
    any of them
}