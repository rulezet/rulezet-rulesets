rule TTP_XOR_QUAD_CurrentVersionRun_f7b4 {
  strings:
    $key_f7b4 = { a4 db [2] 80 d5 [2] ab f9 [2] 85 db [2] 91 c0 [2] 9e da [2] 80 c7 [2] 82 c6 [2] 99 c0 [2] 85 c7 [2] 99 e8 }

  condition:
    any of them
}