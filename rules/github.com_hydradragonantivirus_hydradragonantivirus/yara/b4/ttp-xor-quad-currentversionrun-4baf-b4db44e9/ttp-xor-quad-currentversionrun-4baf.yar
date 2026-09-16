rule TTP_XOR_QUAD_CurrentVersionRun_4baf {
  strings:
    $key_4baf = { 18 c0 [2] 3c ce [2] 17 e2 [2] 39 c0 [2] 2d db [2] 22 c1 [2] 3c dc [2] 3e dd [2] 25 db [2] 39 dc [2] 25 f3 }

  condition:
    any of them
}