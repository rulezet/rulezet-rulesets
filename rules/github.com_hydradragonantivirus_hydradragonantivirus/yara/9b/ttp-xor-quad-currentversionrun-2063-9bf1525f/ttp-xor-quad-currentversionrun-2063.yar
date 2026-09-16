rule TTP_XOR_QUAD_CurrentVersionRun_2063 {
  strings:
    $key_2063 = { 73 0c [2] 57 02 [2] 7c 2e [2] 52 0c [2] 46 17 [2] 49 0d [2] 57 10 [2] 55 11 [2] 4e 17 [2] 52 10 [2] 4e 3f }

  condition:
    any of them
}