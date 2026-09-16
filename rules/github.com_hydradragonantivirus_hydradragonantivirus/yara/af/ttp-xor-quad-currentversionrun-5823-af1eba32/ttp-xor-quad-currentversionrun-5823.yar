rule TTP_XOR_QUAD_CurrentVersionRun_5823 {
  strings:
    $key_5823 = { 0b 4c [2] 2f 42 [2] 04 6e [2] 2a 4c [2] 3e 57 [2] 31 4d [2] 2f 50 [2] 2d 51 [2] 36 57 [2] 2a 50 [2] 36 7f }

  condition:
    any of them
}