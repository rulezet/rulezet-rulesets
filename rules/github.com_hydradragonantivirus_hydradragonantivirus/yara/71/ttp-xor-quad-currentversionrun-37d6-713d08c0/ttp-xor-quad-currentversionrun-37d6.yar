rule TTP_XOR_QUAD_CurrentVersionRun_37d6 {
  strings:
    $key_37d6 = { 64 b9 [2] 40 b7 [2] 6b 9b [2] 45 b9 [2] 51 a2 [2] 5e b8 [2] 40 a5 [2] 42 a4 [2] 59 a2 [2] 45 a5 [2] 59 8a }

  condition:
    any of them
}