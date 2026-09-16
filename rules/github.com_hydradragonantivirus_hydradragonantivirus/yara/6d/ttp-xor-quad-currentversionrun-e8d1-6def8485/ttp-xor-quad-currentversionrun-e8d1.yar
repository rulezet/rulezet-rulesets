rule TTP_XOR_QUAD_CurrentVersionRun_e8d1 {
  strings:
    $key_e8d1 = { bb be [2] 9f b0 [2] b4 9c [2] 9a be [2] 8e a5 [2] 81 bf [2] 9f a2 [2] 9d a3 [2] 86 a5 [2] 9a a2 [2] 86 8d }

  condition:
    any of them
}