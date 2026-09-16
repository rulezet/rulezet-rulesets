rule TTP_XOR_QUAD_CurrentVersionRun_05c2 {
  strings:
    $key_05c2 = { 56 ad [2] 72 a3 [2] 59 8f [2] 77 ad [2] 63 b6 [2] 6c ac [2] 72 b1 [2] 70 b0 [2] 6b b6 [2] 77 b1 [2] 6b 9e }

  condition:
    any of them
}