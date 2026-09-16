rule TTP_XOR_QUAD_CurrentVersionRun_4413 {
  strings:
    $key_4413 = { 17 7c [2] 33 72 [2] 18 5e [2] 36 7c [2] 22 67 [2] 2d 7d [2] 33 60 [2] 31 61 [2] 2a 67 [2] 36 60 [2] 2a 4f }

  condition:
    any of them
}