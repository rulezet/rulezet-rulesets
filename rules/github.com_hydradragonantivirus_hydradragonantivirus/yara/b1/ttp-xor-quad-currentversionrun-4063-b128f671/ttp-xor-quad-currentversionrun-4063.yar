rule TTP_XOR_QUAD_CurrentVersionRun_4063 {
  strings:
    $key_4063 = { 13 0c [2] 37 02 [2] 1c 2e [2] 32 0c [2] 26 17 [2] 29 0d [2] 37 10 [2] 35 11 [2] 2e 17 [2] 32 10 [2] 2e 3f }

  condition:
    any of them
}