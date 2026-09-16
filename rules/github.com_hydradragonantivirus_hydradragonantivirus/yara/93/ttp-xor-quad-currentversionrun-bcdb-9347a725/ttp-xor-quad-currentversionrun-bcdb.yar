rule TTP_XOR_QUAD_CurrentVersionRun_bcdb {
  strings:
    $key_bcdb = { ef b4 [2] cb ba [2] e0 96 [2] ce b4 [2] da af [2] d5 b5 [2] cb a8 [2] c9 a9 [2] d2 af [2] ce a8 [2] d2 87 }

  condition:
    any of them
}