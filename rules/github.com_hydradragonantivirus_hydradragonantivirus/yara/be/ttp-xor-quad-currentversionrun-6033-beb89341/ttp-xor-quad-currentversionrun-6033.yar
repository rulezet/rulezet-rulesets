rule TTP_XOR_QUAD_CurrentVersionRun_6033 {
  strings:
    $key_6033 = { 33 5c [2] 17 52 [2] 3c 7e [2] 12 5c [2] 06 47 [2] 09 5d [2] 17 40 [2] 15 41 [2] 0e 47 [2] 12 40 [2] 0e 6f }

  condition:
    any of them
}