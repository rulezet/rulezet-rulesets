rule TTP_XOR_QUAD_CurrentVersionRun_bcc8 {
  strings:
    $key_bcc8 = { ef a7 [2] cb a9 [2] e0 85 [2] ce a7 [2] da bc [2] d5 a6 [2] cb bb [2] c9 ba [2] d2 bc [2] ce bb [2] d2 94 }

  condition:
    any of them
}