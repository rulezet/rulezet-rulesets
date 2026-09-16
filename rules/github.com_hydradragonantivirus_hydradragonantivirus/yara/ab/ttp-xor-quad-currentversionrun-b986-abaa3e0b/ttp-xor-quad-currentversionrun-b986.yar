rule TTP_XOR_QUAD_CurrentVersionRun_b986 {
  strings:
    $key_b986 = { ea e9 [2] ce e7 [2] e5 cb [2] cb e9 [2] df f2 [2] d0 e8 [2] ce f5 [2] cc f4 [2] d7 f2 [2] cb f5 [2] d7 da }

  condition:
    any of them
}