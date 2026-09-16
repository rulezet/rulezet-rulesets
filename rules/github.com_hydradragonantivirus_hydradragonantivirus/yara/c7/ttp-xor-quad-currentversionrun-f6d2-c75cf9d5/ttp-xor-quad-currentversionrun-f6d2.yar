rule TTP_XOR_QUAD_CurrentVersionRun_f6d2 {
  strings:
    $key_f6d2 = { a5 bd [2] 81 b3 [2] aa 9f [2] 84 bd [2] 90 a6 [2] 9f bc [2] 81 a1 [2] 83 a0 [2] 98 a6 [2] 84 a1 [2] 98 8e }

  condition:
    any of them
}