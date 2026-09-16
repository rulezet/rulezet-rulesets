rule TTP_XOR_QUAD_CurrentVersionRun_69d1 {
  strings:
    $key_69d1 = { 3a be [2] 1e b0 [2] 35 9c [2] 1b be [2] 0f a5 [2] 00 bf [2] 1e a2 [2] 1c a3 [2] 07 a5 [2] 1b a2 [2] 07 8d }

  condition:
    any of them
}