rule TTP_XOR_QUAD_CurrentVersionRun_37c7 {
  strings:
    $key_37c7 = { 64 a8 [2] 40 a6 [2] 6b 8a [2] 45 a8 [2] 51 b3 [2] 5e a9 [2] 40 b4 [2] 42 b5 [2] 59 b3 [2] 45 b4 [2] 59 9b }

  condition:
    any of them
}