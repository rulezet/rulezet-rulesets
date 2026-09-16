rule TTP_XOR_QUAD_CurrentVersionRun_6923 {
  strings:
    $key_6923 = { 3a 4c [2] 1e 42 [2] 35 6e [2] 1b 4c [2] 0f 57 [2] 00 4d [2] 1e 50 [2] 1c 51 [2] 07 57 [2] 1b 50 [2] 07 7f }

  condition:
    any of them
}