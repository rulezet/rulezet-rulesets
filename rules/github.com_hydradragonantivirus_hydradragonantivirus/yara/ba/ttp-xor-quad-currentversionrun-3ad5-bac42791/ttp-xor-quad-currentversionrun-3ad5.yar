rule TTP_XOR_QUAD_CurrentVersionRun_3ad5 {
  strings:
    $key_3ad5 = { 69 ba [2] 4d b4 [2] 66 98 [2] 48 ba [2] 5c a1 [2] 53 bb [2] 4d a6 [2] 4f a7 [2] 54 a1 [2] 48 a6 [2] 54 89 }

  condition:
    any of them
}