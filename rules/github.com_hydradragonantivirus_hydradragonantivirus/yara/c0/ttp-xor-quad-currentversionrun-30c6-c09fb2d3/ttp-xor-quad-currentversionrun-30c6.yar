rule TTP_XOR_QUAD_CurrentVersionRun_30c6 {
  strings:
    $key_30c6 = { 63 a9 [2] 47 a7 [2] 6c 8b [2] 42 a9 [2] 56 b2 [2] 59 a8 [2] 47 b5 [2] 45 b4 [2] 5e b2 [2] 42 b5 [2] 5e 9a }

  condition:
    any of them
}