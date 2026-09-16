rule TTP_XOR_QUAD_CurrentVersionRun_bcc3 {
  strings:
    $key_bcc3 = { ef ac [2] cb a2 [2] e0 8e [2] ce ac [2] da b7 [2] d5 ad [2] cb b0 [2] c9 b1 [2] d2 b7 [2] ce b0 [2] d2 9f }

  condition:
    any of them
}