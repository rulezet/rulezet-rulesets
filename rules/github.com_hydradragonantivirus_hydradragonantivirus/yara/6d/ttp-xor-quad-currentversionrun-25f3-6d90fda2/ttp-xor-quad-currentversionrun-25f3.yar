rule TTP_XOR_QUAD_CurrentVersionRun_25f3 {
  strings:
    $key_25f3 = { 76 9c [2] 52 92 [2] 79 be [2] 57 9c [2] 43 87 [2] 4c 9d [2] 52 80 [2] 50 81 [2] 4b 87 [2] 57 80 [2] 4b af }

  condition:
    any of them
}