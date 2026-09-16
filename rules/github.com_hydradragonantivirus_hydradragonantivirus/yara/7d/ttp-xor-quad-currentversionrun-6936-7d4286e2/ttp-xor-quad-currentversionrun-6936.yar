rule TTP_XOR_QUAD_CurrentVersionRun_6936 {
  strings:
    $key_6936 = { 3a 59 [2] 1e 57 [2] 35 7b [2] 1b 59 [2] 0f 42 [2] 00 58 [2] 1e 45 [2] 1c 44 [2] 07 42 [2] 1b 45 [2] 07 6a }

  condition:
    any of them
}