rule TTP_XOR_QUAD_CurrentVersionRun_0eaf {
  strings:
    $key_0eaf = { 5d c0 [2] 79 ce [2] 52 e2 [2] 7c c0 [2] 68 db [2] 67 c1 [2] 79 dc [2] 7b dd [2] 60 db [2] 7c dc [2] 60 f3 }

  condition:
    any of them
}