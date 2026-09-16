rule TTP_XOR_QUAD_CurrentVersionRun_0cf3 {
  strings:
    $key_0cf3 = { 5f 9c [2] 7b 92 [2] 50 be [2] 7e 9c [2] 6a 87 [2] 65 9d [2] 7b 80 [2] 79 81 [2] 62 87 [2] 7e 80 [2] 62 af }

  condition:
    any of them
}