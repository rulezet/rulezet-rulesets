rule TTP_XOR_QUAD_CurrentVersionRun_5a13 {
  strings:
    $key_5a13 = { 09 7c [2] 2d 72 [2] 06 5e [2] 28 7c [2] 3c 67 [2] 33 7d [2] 2d 60 [2] 2f 61 [2] 34 67 [2] 28 60 [2] 34 4f }

  condition:
    any of them
}