rule TTP_XOR_QUAD_CurrentVersionRun_6303 {
  strings:
    $key_6303 = { 30 6c [2] 14 62 [2] 3f 4e [2] 11 6c [2] 05 77 [2] 0a 6d [2] 14 70 [2] 16 71 [2] 0d 77 [2] 11 70 [2] 0d 5f }

  condition:
    any of them
}