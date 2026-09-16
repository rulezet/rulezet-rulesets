rule TTP_XOR_QUAD_CurrentVersionRun_37d2 {
  strings:
    $key_37d2 = { 64 bd [2] 40 b3 [2] 6b 9f [2] 45 bd [2] 51 a6 [2] 5e bc [2] 40 a1 [2] 42 a0 [2] 59 a6 [2] 45 a1 [2] 59 8e }

  condition:
    any of them
}