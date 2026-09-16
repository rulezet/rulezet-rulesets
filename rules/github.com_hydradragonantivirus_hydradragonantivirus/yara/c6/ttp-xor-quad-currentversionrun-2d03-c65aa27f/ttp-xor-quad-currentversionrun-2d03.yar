rule TTP_XOR_QUAD_CurrentVersionRun_2d03 {
  strings:
    $key_2d03 = { 7e 6c [2] 5a 62 [2] 71 4e [2] 5f 6c [2] 4b 77 [2] 44 6d [2] 5a 70 [2] 58 71 [2] 43 77 [2] 5f 70 [2] 43 5f }

  condition:
    any of them
}