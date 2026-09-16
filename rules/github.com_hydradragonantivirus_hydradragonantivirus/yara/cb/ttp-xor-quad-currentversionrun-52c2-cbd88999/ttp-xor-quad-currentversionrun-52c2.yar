rule TTP_XOR_QUAD_CurrentVersionRun_52c2 {
  strings:
    $key_52c2 = { 01 ad [2] 25 a3 [2] 0e 8f [2] 20 ad [2] 34 b6 [2] 3b ac [2] 25 b1 [2] 27 b0 [2] 3c b6 [2] 20 b1 [2] 3c 9e }

  condition:
    any of them
}