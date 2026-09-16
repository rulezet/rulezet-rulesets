rule TTP_XOR_QUAD_CurrentVersionRun_f6ca {
  strings:
    $key_f6ca = { a5 a5 [2] 81 ab [2] aa 87 [2] 84 a5 [2] 90 be [2] 9f a4 [2] 81 b9 [2] 83 b8 [2] 98 be [2] 84 b9 [2] 98 96 }

  condition:
    any of them
}