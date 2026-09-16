rule TTP_XOR_QUAD_CurrentVersionRun_f8d1 {
  strings:
    $key_f8d1 = { ab be [2] 8f b0 [2] a4 9c [2] 8a be [2] 9e a5 [2] 91 bf [2] 8f a2 [2] 8d a3 [2] 96 a5 [2] 8a a2 [2] 96 8d }

  condition:
    any of them
}