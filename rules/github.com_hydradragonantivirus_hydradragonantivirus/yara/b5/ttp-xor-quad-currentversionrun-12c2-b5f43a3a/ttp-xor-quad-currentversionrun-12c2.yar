rule TTP_XOR_QUAD_CurrentVersionRun_12c2 {
  strings:
    $key_12c2 = { 41 ad [2] 65 a3 [2] 4e 8f [2] 60 ad [2] 74 b6 [2] 7b ac [2] 65 b1 [2] 67 b0 [2] 7c b6 [2] 60 b1 [2] 7c 9e }

  condition:
    any of them
}