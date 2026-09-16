rule TTP_XOR_QUAD_CurrentVersionRun_f5ca {
  strings:
    $key_f5ca = { a6 a5 [2] 82 ab [2] a9 87 [2] 87 a5 [2] 93 be [2] 9c a4 [2] 82 b9 [2] 80 b8 [2] 9b be [2] 87 b9 [2] 9b 96 }

  condition:
    any of them
}