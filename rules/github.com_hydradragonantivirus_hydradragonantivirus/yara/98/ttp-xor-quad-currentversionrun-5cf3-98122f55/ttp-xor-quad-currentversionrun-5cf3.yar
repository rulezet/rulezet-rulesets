rule TTP_XOR_QUAD_CurrentVersionRun_5cf3 {
  strings:
    $key_5cf3 = { 0f 9c [2] 2b 92 [2] 00 be [2] 2e 9c [2] 3a 87 [2] 35 9d [2] 2b 80 [2] 29 81 [2] 32 87 [2] 2e 80 [2] 32 af }

  condition:
    any of them
}