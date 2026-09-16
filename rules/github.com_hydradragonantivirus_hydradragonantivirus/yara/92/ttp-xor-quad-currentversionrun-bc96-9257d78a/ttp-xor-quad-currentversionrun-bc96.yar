rule TTP_XOR_QUAD_CurrentVersionRun_bc96 {
  strings:
    $key_bc96 = { ef f9 [2] cb f7 [2] e0 db [2] ce f9 [2] da e2 [2] d5 f8 [2] cb e5 [2] c9 e4 [2] d2 e2 [2] ce e5 [2] d2 ca }

  condition:
    any of them
}