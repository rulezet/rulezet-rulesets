rule TTP_XOR_QUAD_CurrentVersionRun_f2c2 {
  strings:
    $key_f2c2 = { a1 ad [2] 85 a3 [2] ae 8f [2] 80 ad [2] 94 b6 [2] 9b ac [2] 85 b1 [2] 87 b0 [2] 9c b6 [2] 80 b1 [2] 9c 9e }

  condition:
    any of them
}