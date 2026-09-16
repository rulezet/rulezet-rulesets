rule TTP_XOR_QUAD_CurrentVersionRun_6f03 {
  strings:
    $key_6f03 = { 3c 6c [2] 18 62 [2] 33 4e [2] 1d 6c [2] 09 77 [2] 06 6d [2] 18 70 [2] 1a 71 [2] 01 77 [2] 1d 70 [2] 01 5f }

  condition:
    any of them
}