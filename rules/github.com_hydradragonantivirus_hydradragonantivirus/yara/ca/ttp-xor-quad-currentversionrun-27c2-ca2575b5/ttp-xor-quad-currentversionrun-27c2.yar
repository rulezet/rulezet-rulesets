rule TTP_XOR_QUAD_CurrentVersionRun_27c2 {
  strings:
    $key_27c2 = { 74 ad [2] 50 a3 [2] 7b 8f [2] 55 ad [2] 41 b6 [2] 4e ac [2] 50 b1 [2] 52 b0 [2] 49 b6 [2] 55 b1 [2] 49 9e }

  condition:
    any of them
}