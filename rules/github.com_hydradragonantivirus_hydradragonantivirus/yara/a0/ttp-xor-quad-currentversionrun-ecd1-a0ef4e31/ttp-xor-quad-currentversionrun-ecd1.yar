rule TTP_XOR_QUAD_CurrentVersionRun_ecd1 {
  strings:
    $key_ecd1 = { bf be [2] 9b b0 [2] b0 9c [2] 9e be [2] 8a a5 [2] 85 bf [2] 9b a2 [2] 99 a3 [2] 82 a5 [2] 9e a2 [2] 82 8d }

  condition:
    any of them
}