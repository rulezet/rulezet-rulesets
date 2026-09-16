rule TTP_XOR_QUAD_CurrentVersionRun_6650 {
  strings:
    $key_6650 = { 35 3f [2] 11 31 [2] 3a 1d [2] 14 3f [2] 00 24 [2] 0f 3e [2] 11 23 [2] 13 22 [2] 08 24 [2] 14 23 [2] 08 0c }

  condition:
    any of them
}