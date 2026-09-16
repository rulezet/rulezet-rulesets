rule TTP_XOR_QUAD_CurrentVersionRun_6403 {
  strings:
    $key_6403 = { 37 6c [2] 13 62 [2] 38 4e [2] 16 6c [2] 02 77 [2] 0d 6d [2] 13 70 [2] 11 71 [2] 0a 77 [2] 16 70 [2] 0a 5f }

  condition:
    any of them
}