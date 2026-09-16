rule TTP_XOR_QUAD_CurrentVersionRun_1ad5 {
  strings:
    $key_1ad5 = { 49 ba [2] 6d b4 [2] 46 98 [2] 68 ba [2] 7c a1 [2] 73 bb [2] 6d a6 [2] 6f a7 [2] 74 a1 [2] 68 a6 [2] 74 89 }

  condition:
    any of them
}