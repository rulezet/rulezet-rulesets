rule TTP_XOR_QUAD_CurrentVersionRun_46d5 {
  strings:
    $key_46d5 = { 15 ba [2] 31 b4 [2] 1a 98 [2] 34 ba [2] 20 a1 [2] 2f bb [2] 31 a6 [2] 33 a7 [2] 28 a1 [2] 34 a6 [2] 28 89 }

  condition:
    any of them
}