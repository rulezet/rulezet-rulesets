rule TTP_XOR_QUAD_CurrentVersionRun_7923 {
  strings:
    $key_7923 = { 2a 4c [2] 0e 42 [2] 25 6e [2] 0b 4c [2] 1f 57 [2] 10 4d [2] 0e 50 [2] 0c 51 [2] 17 57 [2] 0b 50 [2] 17 7f }

  condition:
    any of them
}