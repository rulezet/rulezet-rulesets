rule TTP_XOR_QUAD_CurrentVersionRun_57d6 {
  strings:
    $key_57d6 = { 04 b9 [2] 20 b7 [2] 0b 9b [2] 25 b9 [2] 31 a2 [2] 3e b8 [2] 20 a5 [2] 22 a4 [2] 39 a2 [2] 25 a5 [2] 39 8a }

  condition:
    any of them
}