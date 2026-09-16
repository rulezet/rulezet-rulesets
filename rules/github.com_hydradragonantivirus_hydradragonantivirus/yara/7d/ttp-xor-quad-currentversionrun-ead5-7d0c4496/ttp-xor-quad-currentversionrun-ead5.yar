rule TTP_XOR_QUAD_CurrentVersionRun_ead5 {
  strings:
    $key_ead5 = { b9 ba [2] 9d b4 [2] b6 98 [2] 98 ba [2] 8c a1 [2] 83 bb [2] 9d a6 [2] 9f a7 [2] 84 a1 [2] 98 a6 [2] 84 89 }

  condition:
    any of them
}