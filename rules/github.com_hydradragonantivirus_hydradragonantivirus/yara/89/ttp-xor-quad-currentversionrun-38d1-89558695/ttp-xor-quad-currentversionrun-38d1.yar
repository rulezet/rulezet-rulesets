rule TTP_XOR_QUAD_CurrentVersionRun_38d1 {
  strings:
    $key_38d1 = { 6b be [2] 4f b0 [2] 64 9c [2] 4a be [2] 5e a5 [2] 51 bf [2] 4f a2 [2] 4d a3 [2] 56 a5 [2] 4a a2 [2] 56 8d }

  condition:
    any of them
}