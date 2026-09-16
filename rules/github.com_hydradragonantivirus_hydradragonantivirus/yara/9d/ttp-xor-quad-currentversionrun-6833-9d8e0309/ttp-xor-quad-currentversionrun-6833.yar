rule TTP_XOR_QUAD_CurrentVersionRun_6833 {
  strings:
    $key_6833 = { 3b 5c [2] 1f 52 [2] 34 7e [2] 1a 5c [2] 0e 47 [2] 01 5d [2] 1f 40 [2] 1d 41 [2] 06 47 [2] 1a 40 [2] 06 6f }

  condition:
    any of them
}