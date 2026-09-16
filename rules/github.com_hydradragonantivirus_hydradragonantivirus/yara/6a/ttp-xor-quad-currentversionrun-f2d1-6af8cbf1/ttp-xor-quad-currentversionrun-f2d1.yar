rule TTP_XOR_QUAD_CurrentVersionRun_f2d1 {
  strings:
    $key_f2d1 = { a1 be [2] 85 b0 [2] ae 9c [2] 80 be [2] 94 a5 [2] 9b bf [2] 85 a2 [2] 87 a3 [2] 9c a5 [2] 80 a2 [2] 9c 8d }

  condition:
    any of them
}