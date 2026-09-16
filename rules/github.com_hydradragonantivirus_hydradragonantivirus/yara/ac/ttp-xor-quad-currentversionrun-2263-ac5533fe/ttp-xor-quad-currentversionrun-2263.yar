rule TTP_XOR_QUAD_CurrentVersionRun_2263 {
  strings:
    $key_2263 = { 71 0c [2] 55 02 [2] 7e 2e [2] 50 0c [2] 44 17 [2] 4b 0d [2] 55 10 [2] 57 11 [2] 4c 17 [2] 50 10 [2] 4c 3f }

  condition:
    any of them
}