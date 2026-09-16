rule TTP_XOR_QUAD_CurrentVersionRun_56d5 {
  strings:
    $key_56d5 = { 05 ba [2] 21 b4 [2] 0a 98 [2] 24 ba [2] 30 a1 [2] 3f bb [2] 21 a6 [2] 23 a7 [2] 38 a1 [2] 24 a6 [2] 38 89 }

  condition:
    any of them
}