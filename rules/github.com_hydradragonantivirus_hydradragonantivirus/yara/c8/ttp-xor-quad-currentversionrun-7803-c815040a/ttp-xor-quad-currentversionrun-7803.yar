rule TTP_XOR_QUAD_CurrentVersionRun_7803 {
  strings:
    $key_7803 = { 2b 6c [2] 0f 62 [2] 24 4e [2] 0a 6c [2] 1e 77 [2] 11 6d [2] 0f 70 [2] 0d 71 [2] 16 77 [2] 0a 70 [2] 16 5f }

  condition:
    any of them
}