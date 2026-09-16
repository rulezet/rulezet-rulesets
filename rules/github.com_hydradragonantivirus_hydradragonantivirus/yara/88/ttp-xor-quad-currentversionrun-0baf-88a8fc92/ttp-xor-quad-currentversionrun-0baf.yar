rule TTP_XOR_QUAD_CurrentVersionRun_0baf {
  strings:
    $key_0baf = { 58 c0 [2] 7c ce [2] 57 e2 [2] 79 c0 [2] 6d db [2] 62 c1 [2] 7c dc [2] 7e dd [2] 65 db [2] 79 dc [2] 65 f3 }

  condition:
    any of them
}