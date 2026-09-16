rule TTP_XOR_QUAD_CurrentVersionRun_37d7 {
  strings:
    $key_37d7 = { 64 b8 [2] 40 b6 [2] 6b 9a [2] 45 b8 [2] 51 a3 [2] 5e b9 [2] 40 a4 [2] 42 a5 [2] 59 a3 [2] 45 a4 [2] 59 8b }

  condition:
    any of them
}