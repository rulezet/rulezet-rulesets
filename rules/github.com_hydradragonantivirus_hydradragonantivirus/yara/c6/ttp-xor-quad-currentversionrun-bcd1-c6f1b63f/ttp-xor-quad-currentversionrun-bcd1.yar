rule TTP_XOR_QUAD_CurrentVersionRun_bcd1 {
  strings:
    $key_bcd1 = { ef be [2] cb b0 [2] e0 9c [2] ce be [2] da a5 [2] d5 bf [2] cb a2 [2] c9 a3 [2] d2 a5 [2] ce a2 [2] d2 8d }

  condition:
    any of them
}