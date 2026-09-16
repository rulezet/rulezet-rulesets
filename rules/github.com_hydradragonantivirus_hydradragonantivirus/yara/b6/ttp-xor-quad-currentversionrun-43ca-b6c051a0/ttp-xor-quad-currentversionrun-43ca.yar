rule TTP_XOR_QUAD_CurrentVersionRun_43ca {
  strings:
    $key_43ca = { 10 a5 [2] 34 ab [2] 1f 87 [2] 31 a5 [2] 25 be [2] 2a a4 [2] 34 b9 [2] 36 b8 [2] 2d be [2] 31 b9 [2] 2d 96 }

  condition:
    any of them
}