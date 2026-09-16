rule TTP_XOR_QUAD_CurrentVersionRun_72d2 {
  strings:
    $key_72d2 = { 21 bd [2] 05 b3 [2] 2e 9f [2] 00 bd [2] 14 a6 [2] 1b bc [2] 05 a1 [2] 07 a0 [2] 1c a6 [2] 00 a1 [2] 1c 8e }

  condition:
    any of them
}