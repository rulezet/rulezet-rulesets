rule TTP_XOR_QUAD_CurrentVersionRun_0cd1 {
  strings:
    $key_0cd1 = { 5f be [2] 7b b0 [2] 50 9c [2] 7e be [2] 6a a5 [2] 65 bf [2] 7b a2 [2] 79 a3 [2] 62 a5 [2] 7e a2 [2] 62 8d }

  condition:
    any of them
}