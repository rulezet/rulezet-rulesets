rule TTP_XOR_QUAD_CurrentVersionRun_23d2 {
  strings:
    $key_23d2 = { 70 bd [2] 54 b3 [2] 7f 9f [2] 51 bd [2] 45 a6 [2] 4a bc [2] 54 a1 [2] 56 a0 [2] 4d a6 [2] 51 a1 [2] 4d 8e }

  condition:
    any of them
}