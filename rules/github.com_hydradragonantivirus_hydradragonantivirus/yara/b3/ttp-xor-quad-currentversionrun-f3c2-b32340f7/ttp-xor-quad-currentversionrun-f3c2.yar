rule TTP_XOR_QUAD_CurrentVersionRun_f3c2 {
  strings:
    $key_f3c2 = { a0 ad [2] 84 a3 [2] af 8f [2] 81 ad [2] 95 b6 [2] 9a ac [2] 84 b1 [2] 86 b0 [2] 9d b6 [2] 81 b1 [2] 9d 9e }

  condition:
    any of them
}