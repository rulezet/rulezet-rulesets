rule TTP_XOR_QUAD_CurrentVersionRun_57d7 {
  strings:
    $key_57d7 = { 04 b8 [2] 20 b6 [2] 0b 9a [2] 25 b8 [2] 31 a3 [2] 3e b9 [2] 20 a4 [2] 22 a5 [2] 39 a3 [2] 25 a4 [2] 39 8b }

  condition:
    any of them
}