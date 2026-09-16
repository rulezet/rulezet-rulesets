rule TTP_XOR_QUAD_CurrentVersionRun_26d2 {
  strings:
    $key_26d2 = { 75 bd [2] 51 b3 [2] 7a 9f [2] 54 bd [2] 40 a6 [2] 4f bc [2] 51 a1 [2] 53 a0 [2] 48 a6 [2] 54 a1 [2] 48 8e }

  condition:
    any of them
}