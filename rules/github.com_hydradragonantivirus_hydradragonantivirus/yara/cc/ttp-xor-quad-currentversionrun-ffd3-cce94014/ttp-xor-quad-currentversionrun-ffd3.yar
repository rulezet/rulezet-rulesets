rule TTP_XOR_QUAD_CurrentVersionRun_ffd3 {
  strings:
    $key_ffd3 = { ac bc [2] 88 b2 [2] a3 9e [2] 8d bc [2] 99 a7 [2] 96 bd [2] 88 a0 [2] 8a a1 [2] 91 a7 [2] 8d a0 [2] 91 8f }

  condition:
    any of them
}