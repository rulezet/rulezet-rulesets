rule TTP_XOR_QUAD_CurrentVersionRun_f6d5 {
  strings:
    $key_f6d5 = { a5 ba [2] 81 b4 [2] aa 98 [2] 84 ba [2] 90 a1 [2] 9f bb [2] 81 a6 [2] 83 a7 [2] 98 a1 [2] 84 a6 [2] 98 89 }

  condition:
    any of them
}