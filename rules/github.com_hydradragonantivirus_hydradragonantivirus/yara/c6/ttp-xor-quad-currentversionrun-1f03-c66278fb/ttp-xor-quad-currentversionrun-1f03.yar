rule TTP_XOR_QUAD_CurrentVersionRun_1f03 {
  strings:
    $key_1f03 = { 4c 6c [2] 68 62 [2] 43 4e [2] 6d 6c [2] 79 77 [2] 76 6d [2] 68 70 [2] 6a 71 [2] 71 77 [2] 6d 70 [2] 71 5f }

  condition:
    any of them
}