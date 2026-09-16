rule TTP_XOR_QUAD_CurrentVersionRun_40d2 {
  strings:
    $key_40d2 = { 13 bd [2] 37 b3 [2] 1c 9f [2] 32 bd [2] 26 a6 [2] 29 bc [2] 37 a1 [2] 35 a0 [2] 2e a6 [2] 32 a1 [2] 2e 8e }

  condition:
    any of them
}