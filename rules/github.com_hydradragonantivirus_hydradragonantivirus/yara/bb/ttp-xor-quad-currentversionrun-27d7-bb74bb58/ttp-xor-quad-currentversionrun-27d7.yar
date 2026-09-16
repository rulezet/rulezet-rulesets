rule TTP_XOR_QUAD_CurrentVersionRun_27d7 {
  strings:
    $key_27d7 = { 74 b8 [2] 50 b6 [2] 7b 9a [2] 55 b8 [2] 41 a3 [2] 4e b9 [2] 50 a4 [2] 52 a5 [2] 49 a3 [2] 55 a4 [2] 49 8b }

  condition:
    any of them
}