rule TTP_XOR_QUAD_CurrentVersionRun_bcc1 {
  strings:
    $key_bcc1 = { ef ae [2] cb a0 [2] e0 8c [2] ce ae [2] da b5 [2] d5 af [2] cb b2 [2] c9 b3 [2] d2 b5 [2] ce b2 [2] d2 9d }

  condition:
    any of them
}