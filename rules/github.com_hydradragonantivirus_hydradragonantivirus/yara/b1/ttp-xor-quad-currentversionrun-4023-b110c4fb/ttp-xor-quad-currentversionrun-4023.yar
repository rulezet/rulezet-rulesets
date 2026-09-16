rule TTP_XOR_QUAD_CurrentVersionRun_4023 {
  strings:
    $key_4023 = { 13 4c [2] 37 42 [2] 1c 6e [2] 32 4c [2] 26 57 [2] 29 4d [2] 37 50 [2] 35 51 [2] 2e 57 [2] 32 50 [2] 2e 7f }

  condition:
    any of them
}