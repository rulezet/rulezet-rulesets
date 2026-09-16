rule TTP_XOR_QUAD_CurrentVersionRun_12d2 {
  strings:
    $key_12d2 = { 41 bd [2] 65 b3 [2] 4e 9f [2] 60 bd [2] 74 a6 [2] 7b bc [2] 65 a1 [2] 67 a0 [2] 7c a6 [2] 60 a1 [2] 7c 8e }

  condition:
    any of them
}