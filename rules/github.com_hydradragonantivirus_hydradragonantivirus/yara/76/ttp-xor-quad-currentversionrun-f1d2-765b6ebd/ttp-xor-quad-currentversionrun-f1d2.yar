rule TTP_XOR_QUAD_CurrentVersionRun_f1d2 {
  strings:
    $key_f1d2 = { a2 bd [2] 86 b3 [2] ad 9f [2] 83 bd [2] 97 a6 [2] 98 bc [2] 86 a1 [2] 84 a0 [2] 9f a6 [2] 83 a1 [2] 9f 8e }

  condition:
    any of them
}