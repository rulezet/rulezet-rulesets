rule TTP_XOR_QUAD_CurrentVersionRun_4103 {
  strings:
    $key_4103 = { 12 6c [2] 36 62 [2] 1d 4e [2] 33 6c [2] 27 77 [2] 28 6d [2] 36 70 [2] 34 71 [2] 2f 77 [2] 33 70 [2] 2f 5f }

  condition:
    any of them
}