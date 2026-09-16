rule TTP_XOR_QUAD_CurrentVersionRun_7303 {
  strings:
    $key_7303 = { 20 6c [2] 04 62 [2] 2f 4e [2] 01 6c [2] 15 77 [2] 1a 6d [2] 04 70 [2] 06 71 [2] 1d 77 [2] 01 70 [2] 1d 5f }

  condition:
    any of them
}