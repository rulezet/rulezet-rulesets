rule TTP_XOR_QUAD_CurrentVersionRun_09d1 {
  strings:
    $key_09d1 = { 5a be [2] 7e b0 [2] 55 9c [2] 7b be [2] 6f a5 [2] 60 bf [2] 7e a2 [2] 7c a3 [2] 67 a5 [2] 7b a2 [2] 67 8d }

  condition:
    any of them
}