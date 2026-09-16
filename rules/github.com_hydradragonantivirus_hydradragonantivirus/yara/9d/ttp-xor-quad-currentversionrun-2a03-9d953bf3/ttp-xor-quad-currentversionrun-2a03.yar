rule TTP_XOR_QUAD_CurrentVersionRun_2a03 {
  strings:
    $key_2a03 = { 79 6c [2] 5d 62 [2] 76 4e [2] 58 6c [2] 4c 77 [2] 43 6d [2] 5d 70 [2] 5f 71 [2] 44 77 [2] 58 70 [2] 44 5f }

  condition:
    any of them
}