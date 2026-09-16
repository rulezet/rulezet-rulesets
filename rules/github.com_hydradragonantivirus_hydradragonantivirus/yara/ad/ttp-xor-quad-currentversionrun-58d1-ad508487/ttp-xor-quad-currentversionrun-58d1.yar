rule TTP_XOR_QUAD_CurrentVersionRun_58d1 {
  strings:
    $key_58d1 = { 0b be [2] 2f b0 [2] 04 9c [2] 2a be [2] 3e a5 [2] 31 bf [2] 2f a2 [2] 2d a3 [2] 36 a5 [2] 2a a2 [2] 36 8d }

  condition:
    any of them
}