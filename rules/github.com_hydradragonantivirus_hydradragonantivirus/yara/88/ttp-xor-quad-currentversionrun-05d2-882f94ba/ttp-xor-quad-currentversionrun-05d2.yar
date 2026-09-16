rule TTP_XOR_QUAD_CurrentVersionRun_05d2 {
  strings:
    $key_05d2 = { 56 bd [2] 72 b3 [2] 59 9f [2] 77 bd [2] 63 a6 [2] 6c bc [2] 72 a1 [2] 70 a0 [2] 6b a6 [2] 77 a1 [2] 6b 8e }

  condition:
    any of them
}