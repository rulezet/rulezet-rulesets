rule TTP_XOR_QUAD_CurrentVersionRun_1d03 {
  strings:
    $key_1d03 = { 4e 6c [2] 6a 62 [2] 41 4e [2] 6f 6c [2] 7b 77 [2] 74 6d [2] 6a 70 [2] 68 71 [2] 73 77 [2] 6f 70 [2] 73 5f }

  condition:
    any of them
}