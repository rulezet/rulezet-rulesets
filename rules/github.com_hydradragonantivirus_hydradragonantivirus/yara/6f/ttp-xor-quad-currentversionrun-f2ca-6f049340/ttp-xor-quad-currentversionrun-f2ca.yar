rule TTP_XOR_QUAD_CurrentVersionRun_f2ca {
  strings:
    $key_f2ca = { a1 a5 [2] 85 ab [2] ae 87 [2] 80 a5 [2] 94 be [2] 9b a4 [2] 85 b9 [2] 87 b8 [2] 9c be [2] 80 b9 [2] 9c 96 }

  condition:
    any of them
}