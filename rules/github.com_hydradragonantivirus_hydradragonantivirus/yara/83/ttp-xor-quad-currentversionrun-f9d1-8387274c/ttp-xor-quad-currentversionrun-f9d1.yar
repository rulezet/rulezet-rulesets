rule TTP_XOR_QUAD_CurrentVersionRun_f9d1 {
  strings:
    $key_f9d1 = { aa be [2] 8e b0 [2] a5 9c [2] 8b be [2] 9f a5 [2] 90 bf [2] 8e a2 [2] 8c a3 [2] 97 a5 [2] 8b a2 [2] 97 8d }

  condition:
    any of them
}