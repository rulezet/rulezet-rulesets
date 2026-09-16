rule TTP_XOR_QUAD_CurrentVersionRun_fbaf {
  strings:
    $key_fbaf = { a8 c0 [2] 8c ce [2] a7 e2 [2] 89 c0 [2] 9d db [2] 92 c1 [2] 8c dc [2] 8e dd [2] 95 db [2] 89 dc [2] 95 f3 }

  condition:
    any of them
}