rule TTP_XOR_QUAD_CurrentVersionRun_e716 {
  strings:
    $key_e716 = { b4 79 [2] 90 77 [2] bb 5b [2] 95 79 [2] 81 62 [2] 8e 78 [2] 90 65 [2] 92 64 [2] 89 62 [2] 95 65 [2] 89 4a }

  condition:
    any of them
}