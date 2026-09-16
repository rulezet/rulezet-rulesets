rule TTP_XOR_QUAD_CurrentVersionRun_0403 {
  strings:
    $key_0403 = { 57 6c [2] 73 62 [2] 58 4e [2] 76 6c [2] 62 77 [2] 6d 6d [2] 73 70 [2] 71 71 [2] 6a 77 [2] 76 70 [2] 6a 5f }

  condition:
    any of them
}