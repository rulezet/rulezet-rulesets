rule TTP_XOR_QUAD_CurrentVersionRun_bc87 {
  strings:
    $key_bc87 = { ef e8 [2] cb e6 [2] e0 ca [2] ce e8 [2] da f3 [2] d5 e9 [2] cb f4 [2] c9 f5 [2] d2 f3 [2] ce f4 [2] d2 db }

  condition:
    any of them
}