rule TTP_XOR_QUAD_CurrentVersionRun_43d2 {
  strings:
    $key_43d2 = { 10 bd [2] 34 b3 [2] 1f 9f [2] 31 bd [2] 25 a6 [2] 2a bc [2] 34 a1 [2] 36 a0 [2] 2d a6 [2] 31 a1 [2] 2d 8e }

  condition:
    any of them
}