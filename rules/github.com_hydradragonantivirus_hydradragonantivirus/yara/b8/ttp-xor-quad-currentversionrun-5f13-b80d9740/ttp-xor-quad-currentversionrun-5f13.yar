rule TTP_XOR_QUAD_CurrentVersionRun_5f13 {
  strings:
    $key_5f13 = { 0c 7c [2] 28 72 [2] 03 5e [2] 2d 7c [2] 39 67 [2] 36 7d [2] 28 60 [2] 2a 61 [2] 31 67 [2] 2d 60 [2] 31 4f }

  condition:
    any of them
}