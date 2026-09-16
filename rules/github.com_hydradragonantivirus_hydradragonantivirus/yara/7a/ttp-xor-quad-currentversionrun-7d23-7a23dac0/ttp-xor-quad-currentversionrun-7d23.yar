rule TTP_XOR_QUAD_CurrentVersionRun_7d23 {
  strings:
    $key_7d23 = { 2e 4c [2] 0a 42 [2] 21 6e [2] 0f 4c [2] 1b 57 [2] 14 4d [2] 0a 50 [2] 08 51 [2] 13 57 [2] 0f 50 [2] 13 7f }

  condition:
    any of them
}