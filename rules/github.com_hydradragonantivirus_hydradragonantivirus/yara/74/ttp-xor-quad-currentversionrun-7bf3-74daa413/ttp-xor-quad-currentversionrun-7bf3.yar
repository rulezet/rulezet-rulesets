rule TTP_XOR_QUAD_CurrentVersionRun_7bf3 {
  strings:
    $key_7bf3 = { 28 9c [2] 0c 92 [2] 27 be [2] 09 9c [2] 1d 87 [2] 12 9d [2] 0c 80 [2] 0e 81 [2] 15 87 [2] 09 80 [2] 15 af }

  condition:
    any of them
}