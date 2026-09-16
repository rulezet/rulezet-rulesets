rule TTP_XOR_QUAD_CurrentVersionRun_bcd9 {
  strings:
    $key_bcd9 = { ef b6 [2] cb b8 [2] e0 94 [2] ce b6 [2] da ad [2] d5 b7 [2] cb aa [2] c9 ab [2] d2 ad [2] ce aa [2] d2 85 }

  condition:
    any of them
}