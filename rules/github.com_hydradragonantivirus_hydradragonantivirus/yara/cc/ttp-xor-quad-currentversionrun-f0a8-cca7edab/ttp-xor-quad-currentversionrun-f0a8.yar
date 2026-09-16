rule TTP_XOR_QUAD_CurrentVersionRun_f0a8 {
  strings:
    $key_f0a8 = { a3 c7 [2] 87 c9 [2] ac e5 [2] 82 c7 [2] 96 dc [2] 99 c6 [2] 87 db [2] 85 da [2] 9e dc [2] 82 db [2] 9e f4 }

  condition:
    any of them
}