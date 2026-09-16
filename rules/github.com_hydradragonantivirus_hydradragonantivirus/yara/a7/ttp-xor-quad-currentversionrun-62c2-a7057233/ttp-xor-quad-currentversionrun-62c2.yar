rule TTP_XOR_QUAD_CurrentVersionRun_62c2 {
  strings:
    $key_62c2 = { 31 ad [2] 15 a3 [2] 3e 8f [2] 10 ad [2] 04 b6 [2] 0b ac [2] 15 b1 [2] 17 b0 [2] 0c b6 [2] 10 b1 [2] 0c 9e }

  condition:
    any of them
}