rule TTP_XOR_QUAD_CurrentVersionRun_2cd1 {
  strings:
    $key_2cd1 = { 7f be [2] 5b b0 [2] 70 9c [2] 5e be [2] 4a a5 [2] 45 bf [2] 5b a2 [2] 59 a3 [2] 42 a5 [2] 5e a2 [2] 42 8d }

  condition:
    any of them
}