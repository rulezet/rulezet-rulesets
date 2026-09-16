rule TTP_XOR_QUAD_CurrentVersionRun_16d2 {
  strings:
    $key_16d2 = { 45 bd [2] 61 b3 [2] 4a 9f [2] 64 bd [2] 70 a6 [2] 7f bc [2] 61 a1 [2] 63 a0 [2] 78 a6 [2] 64 a1 [2] 78 8e }

  condition:
    any of them
}