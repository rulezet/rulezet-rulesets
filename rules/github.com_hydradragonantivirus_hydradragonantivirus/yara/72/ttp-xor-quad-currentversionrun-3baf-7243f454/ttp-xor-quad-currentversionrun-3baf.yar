rule TTP_XOR_QUAD_CurrentVersionRun_3baf {
  strings:
    $key_3baf = { 68 c0 [2] 4c ce [2] 67 e2 [2] 49 c0 [2] 5d db [2] 52 c1 [2] 4c dc [2] 4e dd [2] 55 db [2] 49 dc [2] 55 f3 }

  condition:
    any of them
}