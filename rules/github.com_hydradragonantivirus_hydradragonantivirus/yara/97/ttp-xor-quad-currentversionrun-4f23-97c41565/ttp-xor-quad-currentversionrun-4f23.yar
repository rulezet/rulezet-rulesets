rule TTP_XOR_QUAD_CurrentVersionRun_4f23 {
  strings:
    $key_4f23 = { 1c 4c [2] 38 42 [2] 13 6e [2] 3d 4c [2] 29 57 [2] 26 4d [2] 38 50 [2] 3a 51 [2] 21 57 [2] 3d 50 [2] 21 7f }

  condition:
    any of them
}