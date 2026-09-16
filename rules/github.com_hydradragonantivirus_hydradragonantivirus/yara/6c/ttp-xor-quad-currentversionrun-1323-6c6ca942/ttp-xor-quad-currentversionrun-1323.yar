rule TTP_XOR_QUAD_CurrentVersionRun_1323 {
  strings:
    $key_1323 = { 40 4c [2] 64 42 [2] 4f 6e [2] 61 4c [2] 75 57 [2] 7a 4d [2] 64 50 [2] 66 51 [2] 7d 57 [2] 61 50 [2] 7d 7f }

  condition:
    any of them
}