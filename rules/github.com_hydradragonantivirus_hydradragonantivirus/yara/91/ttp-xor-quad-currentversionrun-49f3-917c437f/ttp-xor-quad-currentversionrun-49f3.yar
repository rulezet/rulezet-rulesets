rule TTP_XOR_QUAD_CurrentVersionRun_49f3 {
  strings:
    $key_49f3 = { 1a 9c [2] 3e 92 [2] 15 be [2] 3b 9c [2] 2f 87 [2] 20 9d [2] 3e 80 [2] 3c 81 [2] 27 87 [2] 3b 80 [2] 27 af }

  condition:
    any of them
}