rule TTP_XOR_QUAD_CurrentVersionRun_32d6 {
  strings:
    $key_32d6 = { 61 b9 [2] 45 b7 [2] 6e 9b [2] 40 b9 [2] 54 a2 [2] 5b b8 [2] 45 a5 [2] 47 a4 [2] 5c a2 [2] 40 a5 [2] 5c 8a }

  condition:
    any of them
}