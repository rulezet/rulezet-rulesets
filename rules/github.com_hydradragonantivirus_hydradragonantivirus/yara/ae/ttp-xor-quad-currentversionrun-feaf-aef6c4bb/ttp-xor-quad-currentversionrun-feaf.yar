rule TTP_XOR_QUAD_CurrentVersionRun_feaf {
  strings:
    $key_feaf = { ad c0 [2] 89 ce [2] a2 e2 [2] 8c c0 [2] 98 db [2] 97 c1 [2] 89 dc [2] 8b dd [2] 90 db [2] 8c dc [2] 90 f3 }

  condition:
    any of them
}