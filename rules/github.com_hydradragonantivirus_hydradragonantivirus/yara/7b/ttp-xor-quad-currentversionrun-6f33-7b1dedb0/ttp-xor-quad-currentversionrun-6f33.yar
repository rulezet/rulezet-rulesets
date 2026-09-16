rule TTP_XOR_QUAD_CurrentVersionRun_6f33 {
  strings:
    $key_6f33 = { 3c 5c [2] 18 52 [2] 33 7e [2] 1d 5c [2] 09 47 [2] 06 5d [2] 18 40 [2] 1a 41 [2] 01 47 [2] 1d 40 [2] 01 6f }

  condition:
    any of them
}