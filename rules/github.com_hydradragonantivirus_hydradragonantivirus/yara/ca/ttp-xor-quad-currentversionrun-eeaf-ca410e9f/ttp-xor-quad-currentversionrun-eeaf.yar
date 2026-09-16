rule TTP_XOR_QUAD_CurrentVersionRun_eeaf {
  strings:
    $key_eeaf = { bd c0 [2] 99 ce [2] b2 e2 [2] 9c c0 [2] 88 db [2] 87 c1 [2] 99 dc [2] 9b dd [2] 80 db [2] 9c dc [2] 80 f3 }

  condition:
    any of them
}