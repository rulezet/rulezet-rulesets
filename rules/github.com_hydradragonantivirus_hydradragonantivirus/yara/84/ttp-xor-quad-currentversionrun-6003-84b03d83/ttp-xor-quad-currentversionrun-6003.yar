rule TTP_XOR_QUAD_CurrentVersionRun_6003 {
  strings:
    $key_6003 = { 33 6c [2] 17 62 [2] 3c 4e [2] 12 6c [2] 06 77 [2] 09 6d [2] 17 70 [2] 15 71 [2] 0e 77 [2] 12 70 [2] 0e 5f }

  condition:
    any of them
}