rule TTP_XOR_QUAD_CurrentVersionRun_5a03 {
  strings:
    $key_5a03 = { 09 6c [2] 2d 62 [2] 06 4e [2] 28 6c [2] 3c 77 [2] 33 6d [2] 2d 70 [2] 2f 71 [2] 34 77 [2] 28 70 [2] 34 5f }

  condition:
    any of them
}