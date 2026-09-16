rule TTP_XOR_QUAD_CurrentVersionRun_26c2 {
  strings:
    $key_26c2 = { 75 ad [2] 51 a3 [2] 7a 8f [2] 54 ad [2] 40 b6 [2] 4f ac [2] 51 b1 [2] 53 b0 [2] 48 b6 [2] 54 b1 [2] 48 9e }

  condition:
    any of them
}