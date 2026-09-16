rule TTP_XOR_QUAD_CurrentVersionRun_50d6 {
  strings:
    $key_50d6 = { 03 b9 [2] 27 b7 [2] 0c 9b [2] 22 b9 [2] 36 a2 [2] 39 b8 [2] 27 a5 [2] 25 a4 [2] 3e a2 [2] 22 a5 [2] 3e 8a }

  condition:
    any of them
}