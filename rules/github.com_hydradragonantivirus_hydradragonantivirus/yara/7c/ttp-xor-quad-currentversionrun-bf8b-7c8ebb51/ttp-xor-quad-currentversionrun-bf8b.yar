rule TTP_XOR_QUAD_CurrentVersionRun_bf8b {
  strings:
    $key_bf8b = { ec e4 [2] c8 ea [2] e3 c6 [2] cd e4 [2] d9 ff [2] d6 e5 [2] c8 f8 [2] ca f9 [2] d1 ff [2] cd f8 [2] d1 d7 }

  condition:
    any of them
}