rule TTP_XOR_QUAD_CurrentVersionRun_5d03 {
  strings:
    $key_5d03 = { 0e 6c [2] 2a 62 [2] 01 4e [2] 2f 6c [2] 3b 77 [2] 34 6d [2] 2a 70 [2] 28 71 [2] 33 77 [2] 2f 70 [2] 33 5f }

  condition:
    any of them
}