rule TTP_XOR_QUAD_CurrentVersionRun_f496 {
  strings:
    $key_f496 = { a7 f9 [2] 83 f7 [2] a8 db [2] 86 f9 [2] 92 e2 [2] 9d f8 [2] 83 e5 [2] 81 e4 [2] 9a e2 [2] 86 e5 [2] 9a ca }

  condition:
    any of them
}