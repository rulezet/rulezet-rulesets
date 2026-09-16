rule TTP_XOR_QUAD_CurrentVersionRun_bcc7 {
  strings:
    $key_bcc7 = { ef a8 [2] cb a6 [2] e0 8a [2] ce a8 [2] da b3 [2] d5 a9 [2] cb b4 [2] c9 b5 [2] d2 b3 [2] ce b4 [2] d2 9b }

  condition:
    any of them
}