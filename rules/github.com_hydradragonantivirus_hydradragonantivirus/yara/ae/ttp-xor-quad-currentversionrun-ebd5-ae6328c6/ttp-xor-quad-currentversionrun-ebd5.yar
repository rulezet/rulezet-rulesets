rule TTP_XOR_QUAD_CurrentVersionRun_ebd5 {
  strings:
    $key_ebd5 = { b8 ba [2] 9c b4 [2] b7 98 [2] 99 ba [2] 8d a1 [2] 82 bb [2] 9c a6 [2] 9e a7 [2] 85 a1 [2] 99 a6 [2] 85 89 }

  condition:
    any of them
}