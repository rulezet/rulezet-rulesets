rule TTP_XOR_QUAD_CurrentVersionRun_06d2 {
  strings:
    $key_06d2 = { 55 bd [2] 71 b3 [2] 5a 9f [2] 74 bd [2] 60 a6 [2] 6f bc [2] 71 a1 [2] 73 a0 [2] 68 a6 [2] 74 a1 [2] 68 8e }

  condition:
    any of them
}