rule TTP_XOR_QUAD_CurrentVersionRun_f0ca {
  strings:
    $key_f0ca = { a3 a5 [2] 87 ab [2] ac 87 [2] 82 a5 [2] 96 be [2] 99 a4 [2] 87 b9 [2] 85 b8 [2] 9e be [2] 82 b9 [2] 9e 96 }

  condition:
    any of them
}