rule TTP_XOR_QUAD_CurrentVersionRun_5223 {
  strings:
    $key_5223 = { 01 4c [2] 25 42 [2] 0e 6e [2] 20 4c [2] 34 57 [2] 3b 4d [2] 25 50 [2] 27 51 [2] 3c 57 [2] 20 50 [2] 3c 7f }

  condition:
    any of them
}