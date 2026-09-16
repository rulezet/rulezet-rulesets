rule TTP_XOR_QUAD_CurrentVersionRun_2eaf {
  strings:
    $key_2eaf = { 7d c0 [2] 59 ce [2] 72 e2 [2] 5c c0 [2] 48 db [2] 47 c1 [2] 59 dc [2] 5b dd [2] 40 db [2] 5c dc [2] 40 f3 }

  condition:
    any of them
}