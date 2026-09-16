rule TTP_XOR_QUAD_CurrentVersionRun_6903 {
  strings:
    $key_6903 = { 3a 6c [2] 1e 62 [2] 35 4e [2] 1b 6c [2] 0f 77 [2] 00 6d [2] 1e 70 [2] 1c 71 [2] 07 77 [2] 1b 70 [2] 07 5f }

  condition:
    any of them
}