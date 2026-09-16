rule TTP_XOR_QUAD_CurrentVersionRun_76c2 {
  strings:
    $key_76c2 = { 25 ad [2] 01 a3 [2] 2a 8f [2] 04 ad [2] 10 b6 [2] 1f ac [2] 01 b1 [2] 03 b0 [2] 18 b6 [2] 04 b1 [2] 18 9e }

  condition:
    any of them
}