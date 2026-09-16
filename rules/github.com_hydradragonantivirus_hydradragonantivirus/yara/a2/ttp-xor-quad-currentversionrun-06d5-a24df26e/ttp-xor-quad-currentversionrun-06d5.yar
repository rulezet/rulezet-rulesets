rule TTP_XOR_QUAD_CurrentVersionRun_06d5 {
  strings:
    $key_06d5 = { 55 ba [2] 71 b4 [2] 5a 98 [2] 74 ba [2] 60 a1 [2] 6f bb [2] 71 a6 [2] 73 a7 [2] 68 a1 [2] 74 a6 [2] 68 89 }

  condition:
    any of them
}