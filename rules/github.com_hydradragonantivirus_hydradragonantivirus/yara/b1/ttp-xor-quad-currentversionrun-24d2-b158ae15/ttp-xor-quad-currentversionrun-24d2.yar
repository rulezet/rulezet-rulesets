rule TTP_XOR_QUAD_CurrentVersionRun_24d2 {
  strings:
    $key_24d2 = { 77 bd [2] 53 b3 [2] 78 9f [2] 56 bd [2] 42 a6 [2] 4d bc [2] 53 a1 [2] 51 a0 [2] 4a a6 [2] 56 a1 [2] 4a 8e }

  condition:
    any of them
}