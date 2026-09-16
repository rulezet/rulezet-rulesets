rule TTP_XOR_QUAD_CurrentVersionRun_e2c7 {
  strings:
    $key_e2c7 = { b1 a8 [2] 95 a6 [2] be 8a [2] 90 a8 [2] 84 b3 [2] 8b a9 [2] 95 b4 [2] 97 b5 [2] 8c b3 [2] 90 b4 [2] 8c 9b }

  condition:
    any of them
}