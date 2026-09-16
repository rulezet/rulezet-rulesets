rule TTP_XOR_QUAD_CurrentVersionRun_15d2 {
  strings:
    $key_15d2 = { 46 bd [2] 62 b3 [2] 49 9f [2] 67 bd [2] 73 a6 [2] 7c bc [2] 62 a1 [2] 60 a0 [2] 7b a6 [2] 67 a1 [2] 7b 8e }

  condition:
    any of them
}