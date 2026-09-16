rule TTP_XOR_QUAD_CurrentVersionRun_79d1 {
  strings:
    $key_79d1 = { 2a be [2] 0e b0 [2] 25 9c [2] 0b be [2] 1f a5 [2] 10 bf [2] 0e a2 [2] 0c a3 [2] 17 a5 [2] 0b a2 [2] 17 8d }

  condition:
    any of them
}