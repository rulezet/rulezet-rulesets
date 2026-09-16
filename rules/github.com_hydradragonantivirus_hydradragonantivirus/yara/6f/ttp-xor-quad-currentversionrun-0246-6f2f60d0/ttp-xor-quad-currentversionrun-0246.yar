rule TTP_XOR_QUAD_CurrentVersionRun_0246 {
  strings:
    $key_0246 = { 51 29 [2] 75 27 [2] 5e 0b [2] 70 29 [2] 64 32 [2] 6b 28 [2] 75 35 [2] 77 34 [2] 6c 32 [2] 70 35 [2] 6c 1a }

  condition:
    any of them
}