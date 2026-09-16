rule TTP_XOR_QUAD_CurrentVersionRun_bf98 {
  strings:
    $key_bf98 = { ec f7 [2] c8 f9 [2] e3 d5 [2] cd f7 [2] d9 ec [2] d6 f6 [2] c8 eb [2] ca ea [2] d1 ec [2] cd eb [2] d1 c4 }

  condition:
    any of them
}