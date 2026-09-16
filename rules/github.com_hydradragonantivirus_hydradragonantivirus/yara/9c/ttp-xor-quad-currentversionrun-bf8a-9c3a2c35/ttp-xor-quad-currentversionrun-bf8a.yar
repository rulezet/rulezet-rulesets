rule TTP_XOR_QUAD_CurrentVersionRun_bf8a {
  strings:
    $key_bf8a = { ec e5 [2] c8 eb [2] e3 c7 [2] cd e5 [2] d9 fe [2] d6 e4 [2] c8 f9 [2] ca f8 [2] d1 fe [2] cd f9 [2] d1 d6 }

  condition:
    any of them
}