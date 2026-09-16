rule TTP_XOR_QUAD_CurrentVersionRun_f5a2 {
  strings:
    $key_f5a2 = { a6 cd [2] 82 c3 [2] a9 ef [2] 87 cd [2] 93 d6 [2] 9c cc [2] 82 d1 [2] 80 d0 [2] 9b d6 [2] 87 d1 [2] 9b fe }

  condition:
    any of them
}