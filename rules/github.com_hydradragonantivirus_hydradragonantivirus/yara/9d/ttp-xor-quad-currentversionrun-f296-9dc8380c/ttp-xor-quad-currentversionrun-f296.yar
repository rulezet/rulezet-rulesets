rule TTP_XOR_QUAD_CurrentVersionRun_f296 {
  strings:
    $key_f296 = { a1 f9 [2] 85 f7 [2] ae db [2] 80 f9 [2] 94 e2 [2] 9b f8 [2] 85 e5 [2] 87 e4 [2] 9c e2 [2] 80 e5 [2] 9c ca }

  condition:
    any of them
}