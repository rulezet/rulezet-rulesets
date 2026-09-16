rule TTP_XOR_QUAD_CurrentVersionRun_b985 {
  strings:
    $key_b985 = { ea ea [2] ce e4 [2] e5 c8 [2] cb ea [2] df f1 [2] d0 eb [2] ce f6 [2] cc f7 [2] d7 f1 [2] cb f6 [2] d7 d9 }

  condition:
    any of them
}